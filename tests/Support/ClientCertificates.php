<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Auth\Providers\Drivers\MtlsDriver;
use Illuminate\Support\Facades\Process;

/**
 * Real X.509 certificates for the `mtls` driver's tests, minted at run time.
 *
 * 🛑 **Minted rather than committed, and that is CLAUDE.md §6 rather than a
 * preference**: "Never commit secrets — no `.env`, no keys, no certificates,
 * not in fixtures, not in test data, not commented out." A certificate is a
 * public document and the private keys here are thrown away within the
 * process, so committing one would leak nothing — and the rule is still the
 * right one, because the next person to add a fixture beside it would not know
 * which of the two it was.
 *
 * ## 🛑 Why the `openssl` binary and not `ext-openssl`
 *
 * {@see self::expiredLeaf()} and {@see self::futureLeaf()} are the reason, and
 * it was measured: `openssl_csr_sign()` takes a **day count** and refuses a
 * negative one —
 *
 * > `openssl_csr_sign(): Days must be between 0 and 106751991167300`
 *
 * — so the extension cannot produce a certificate outside its validity window
 * at all. `days: 0` sets `notAfter` to the signing second, which expires
 * somewhere between zero and one second later: a test that passes or fails on
 * which side of a second boundary it ran. OpenSSL 3.x's `-not_before` and
 * `-not_after` give exact instants, so the fixtures are deterministic.
 *
 * P-256 keys rather than RSA because every certificate here is generated per
 * process and an EC keypair is roughly two orders of magnitude cheaper to
 * produce than a 2048-bit RSA one.
 */
final class ClientCertificates
{
    /**
     * 🛑 Generated **once per process** and reused, because the suite asks for
     * the same certificates in dozens of tests and each one is a subprocess.
     *
     * @var array<string, string>
     */
    private static array $cache = [];

    /** The issuer DN every certificate here is signed by, as an operator would write it. */
    public const string ISSUER_DN = 'C=GB, O=DocUp Test, CN=DocUp Test Issuing CA';

    /** A valid leaf: `CN=alice`, with `alice@example.com` in the subject alternative name. */
    public static function leaf(): string
    {
        return self::mint('leaf', ['-days', '30', '-copy_extensions', 'copy']);
    }

    /**
     * A leaf whose validity window closed in 2020.
     *
     * The reader's own fault and §8.12.23's case (a): they hold a certificate
     * for this installation, so a challenge tells them nothing they did not
     * know.
     */
    public static function expiredLeaf(): string
    {
        return self::mint('expired', [
            '-not_before', '20200101000000Z',
            '-not_after', '20200102000000Z',
            '-copy_extensions', 'copy',
        ]);
    }

    /** A leaf whose validity window opens in 2040 — a clock skew, or pre-issuance. */
    public static function futureLeaf(): string
    {
        return self::mint('future', [
            '-not_before', '20400101000000Z',
            '-not_after', '20400102000000Z',
            '-copy_extensions', 'copy',
        ]);
    }

    /**
     * 🛑 A leaf with **two** `CN` attributes, which OpenSSL reports as an array.
     *
     * The shape `MtlsRejection::SubjectAmbiguous` exists for, and the one a
     * driver reading `$subject['CN']` as a string would turn into the literal
     * `"Array"`.
     */
    public static function twoCommonNames(): string
    {
        return self::mint('two-cn', ['-days', '30'], subject: '/CN=alice/CN=bob');
    }

    /** A leaf carrying `emailAddress` in the subject DN rather than in the SAN. */
    public static function leafWithEmailInTheDn(): string
    {
        return self::mint(
            'dn-email',
            ['-days', '30'],
            subject: '/C=GB/O=DocUp Test/CN=alice/emailAddress=alice@example.com',
        );
    }

    /**
     * 🛑 A leaf signed by a **different** CA that spells its issuer DN
     * identically.
     *
     * The forgery {@see MtlsDriver} is honest about
     * being unable to detect: the issuer DN is a field in a document the
     * attacker wrote. It is refused by the *terminator's verdict* and by
     * nothing else, which is why that verdict is mandatory.
     */
    public static function leafFromAnImpostorCa(): string
    {
        return self::mint('impostor', ['-days', '30'], ca: 'impostor');
    }

    /** A leaf from a CA with a genuinely different DN, for the issuer pin. */
    public static function leafFromAnotherIssuer(): string
    {
        return self::mint('other-ca', ['-days', '30'], ca: 'other');
    }

    /** The SHA-256 fingerprint of a PEM, lower-case hex with no separators. */
    public static function fingerprintOf(string $pem): string
    {
        $fingerprint = openssl_x509_fingerprint($pem, 'sha256');

        if (! is_string($fingerprint)) {
            throw new \RuntimeException('could not fingerprint the fixture certificate');
        }

        return strtolower($fingerprint);
    }

    /** nginx's `$ssl_client_escaped_cert`: the PEM, URL-encoded. */
    public static function asEscapedPem(string $pem): string
    {
        return rawurlencode($pem);
    }

    /** Caddy's and HAProxy's spelling: base64 of the DER. */
    public static function asDerBase64(string $pem): string
    {
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----|\s+/', '', $pem) ?? '';

        return $body;
    }

    /**
     * One certificate, minted and cached.
     *
     * @param  list<string>  $validity  the `openssl x509` arguments that fix
     *                                  the validity window
     */
    private static function mint(
        string $key,
        array $validity,
        string $subject = '/C=GB/O=DocUp Test/CN=alice',
        string $ca = 'ca',
    ): string {
        if (isset(self::$cache[$key])) {
            return self::$cache[$key];
        }

        $dir = self::workspace();

        self::authority($dir, $ca, match ($ca) {
            /*
             * 🛑 The impostor's DN is byte-identical to the real CA's, which
             * is the whole point of that fixture.
             */
            'impostor' => '/C=GB/O=DocUp Test/CN=DocUp Test Issuing CA',
            'other' => '/C=GB/O=Somebody Else/CN=Somebody Else Root',
            default => '/C=GB/O=DocUp Test/CN=DocUp Test Issuing CA',
        });

        /*
         * 🛑 The leaf's files are prefixed `leaf-`, and the prefix is a bug
         * fix rather than tidiness. Without it `mint('impostor', ca:
         * 'impostor')` wrote the LEAF's private key over the authority's — same
         * name, same directory — and `openssl x509 -req` then failed with "CA
         * certificate and CA private key do not match". The fixture that found
         * it is the one that signs with a CA of its own name; the others
         * escaped by having two different names, which is exactly the kind of
         * near miss worth removing rather than renaming around.
         */
        self::openssl([
            'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
            '-keyout', $dir.'/leaf-'.$key.'.key', '-out', $dir.'/leaf-'.$key.'.csr',
            '-subj', $subject,
            '-addext', 'subjectAltName=email:alice@example.com',
        ]);

        self::openssl(array_merge([
            'x509', '-req', '-in', $dir.'/leaf-'.$key.'.csr',
            '-CA', $dir.'/'.$ca.'.crt', '-CAkey', $dir.'/'.$ca.'.key',
            '-out', $dir.'/leaf-'.$key.'.crt', '-sha256',
        ], $validity));

        $pem = file_get_contents($dir.'/leaf-'.$key.'.crt');

        if ($pem === false) {
            throw new \RuntimeException('openssl produced no certificate for '.$key);
        }

        return self::$cache[$key] = $pem;
    }

    /** A self-signed authority, minted once per name. */
    private static function authority(string $dir, string $name, string $subject): void
    {
        if (is_file($dir.'/'.$name.'.crt')) {
            return;
        }

        self::openssl([
            'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-noenc',
            '-keyout', $dir.'/'.$name.'.key', '-out', $dir.'/'.$name.'.crt',
            '-days', '3650', '-subj', $subject,
        ]);
    }

    /**
     * 🛑 The workspace is per **process** and under the system temp directory,
     * never in the repository.
     *
     * A private key written into the checkout is one `git add` away from being
     * committed for ever, and CLAUDE.md §6's rule about staging explicit paths
     * is the only thing that would have stopped it.
     */
    private static function workspace(): string
    {
        static $dir = null;

        if (is_string($dir)) {
            return $dir;
        }

        $dir = sys_get_temp_dir().'/docup-mtls-'.bin2hex(random_bytes(8));

        if (! mkdir($dir, 0o700, true) && ! is_dir($dir)) {
            throw new \RuntimeException('could not create a certificate workspace at '.$dir);
        }

        return $dir;
    }

    /**
     * @param  list<string>  $arguments
     */
    private static function openssl(array $arguments): void
    {
        $result = Process::run(array_merge(['openssl'], $arguments));

        if (! $result->successful()) {
            throw new \RuntimeException(
                'openssl '.($arguments[0] ?? '?').' failed: '.$result->errorOutput(),
            );
        }
    }
}
