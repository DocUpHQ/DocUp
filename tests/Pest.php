<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);
use Tests\TestCase;

/*
|------------------------------------------------------------------------------
| Test bootstrap
|------------------------------------------------------------------------------
| The SPEC 9.4 architecture presets live in tests/Arch/PresetsTest.php, not
| here. Top-level arch() calls in this file were silently NOT collected - a
| deliberately false expectation still reported a green run - so they are in a
| real test file where Pest collects them and names them individually.
*/

pest()->extend(TestCase::class)->in('Feature');
