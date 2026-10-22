<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    'login' => [
        'title' => 'Connexion',
        'subtitle' => 'Connectez-vous au portail de documentation',
        'email' => 'Adresse e-mail',
        'password' => 'Mot de passe',
        'submit' => 'Se connecter',
        'phase_notice' => 'L’authentification arrivera à la phase 02.',
        'locale_label' => 'Langue',
    ],

    /*
    | §8.13.5 step-up re-authentication.
    */
    'confirm' => [
        'title' => 'Confirmez votre mot de passe',
        'intro' => 'Cette action est sensible : veuillez confirmer votre mot de passe pour continuer.',
        'password' => 'Mot de passe',
        'submit' => 'Confirmer',
    ],

    /*
    | §8.13.4 authentification à deux facteurs.
    */
    'two_factor' => [
        'title' => 'Authentification à deux facteurs',
        'intro' => "Saisissez le code de votre application d'authentification.",
        'code' => 'Code de vérification',
        'recovery_prompt' => 'Utiliser un code de récupération',
        'recovery_code' => 'Code de récupération',
        'submit' => 'Continuer',
    ],

    'forgot' => [
        'title' => 'Réinitialiser votre mot de passe',
        'intro' => 'Nous vous enverrons un lien pour choisir un nouveau mot de passe.',
        'email' => 'Adresse e-mail',
        'submit' => 'Envoyer le lien',
    ],

    'reset' => [
        'title' => 'Choisir un nouveau mot de passe',
        'password' => 'Nouveau mot de passe',
        'confirm' => 'Confirmer le nouveau mot de passe',
        'submit' => 'Enregistrer',
    ],

    'failed' => 'Ces identifiants ne correspondent à aucun compte.',
    'throttle' => 'Trop de tentatives. Veuillez réessayer dans :seconds secondes.',

];
