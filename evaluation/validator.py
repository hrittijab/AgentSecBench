import argparse
import json

from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ATTACKS = (
    ROOT / "attacks" / "generated_attacks.json"
)

LEGACY_MODES = {
    "baseline",
    "defended",
}

CURRENT_MODES = {
    "baseline",
    "prompt_guard",
    "authorization",
    "layered",
}

KNOWN_MODES = LEGACY_MODES | CURRENT_MODES


def load_json(path):
    with Path(path).open(
        encoding="utf-8"
    ) as f:
        return json.load(f)


def detect_required_modes(results):
    """
    Determine the experiment schema represented by results.

    Legacy v1 results use:
        baseline + defended

    Current v1.1 results use named defense strategies.

    Important:
    A baseline-only result is treated as an incomplete legacy
    baseline/defended experiment unless named-defense metadata
    establishes that it belongs to the newer schema.
    """

    represented = {
        trial.get("mode")
        for trial in results
        if trial.get("mode") in KNOWN_MODES
    }

    # Explicit legacy defended records establish the v1 schema.
    if "defended" in represented:
        return LEGACY_MODES

    # Any named non-baseline defense establishes the v1.1
    # named-defense schema.
    named_defenses = represented & {
        "prompt_guard",
        "authorization",
        "layered",
    }

    if named_defenses:
        required = set(named_defenses)

        if "baseline" in represented:
            required.add("baseline")

        return required

    # A baseline-only result cannot prove that baseline was
    # intentionally the only selected defense. Preserve the
    # historical validator behavior and require its legacy pair.
    if represented == {"baseline"}:
        return LEGACY_MODES

    return represented


def validate_experiment(
    results,
    attacks,
    allow_partial=False,
    required_modes=None,
):
    """
    Validate benchmark integrity.

    Checks:
    - duplicate trial records
    - missing required defense/mode records
    - unknown attack IDs
    - category mismatches
    - malformed execution records
    - missing or inconsistent metadata
    - experiment provenance consistency
    - defense/mode consistency

    Supports both legacy v1 baseline/defended results and
    v1.1 named-defense results.

    Does not change benchmark results.
    """

    errors = []
    warnings = []

    attack_map = {}
    attack_counts = Counter()

    for attack in attacks:
        attack_id = attack.get("attack_id")

        if not attack_id:
            errors.append(
                "Attack definition missing attack_id"
            )
            continue

        attack_counts[attack_id] += 1
        attack_map[attack_id] = attack

    for attack_id, count in attack_counts.items():
        if count > 1:
            errors.append(
                f"Duplicate attack definition: {attack_id}"
            )

    if required_modes is None:
        required_modes = detect_required_modes(
            results
        )
    else:
        required_modes = set(required_modes)

    unknown_required = (
        required_modes - KNOWN_MODES
    )

    if unknown_required:
        errors.append(
            "Unknown required mode(s): "
            f"{sorted(unknown_required)}"
        )

    if not required_modes and results:
        errors.append(
            "Could not determine required experiment modes"
        )

    # Do not allow legacy and current naming schemes to be
    # combined in one experiment.
    if (
        "defended" in required_modes
        and (
            "authorization" in required_modes
            or "prompt_guard" in required_modes
            or "layered" in required_modes
        )
    ):
        errors.append(
            "Experiment mixes legacy 'defended' mode "
            "with named defense strategies"
        )

    seen = Counter()
    grouped = defaultdict(set)
    statuses = Counter()

    experiment_ids = set()
    runner_versions = set()
    dataset_hashes = set()

    for index, trial in enumerate(results):
        attack_id = trial.get("attack_id")
        mode = trial.get("mode")

        if not attack_id:
            errors.append(
                f"Trial {index}: missing attack_id"
            )
            continue

        if mode not in KNOWN_MODES:
            errors.append(
                f"{attack_id}: invalid mode {mode}"
            )
            continue

        if (
            required_modes
            and mode not in required_modes
        ):
            errors.append(
                f"{attack_id}: unexpected mode {mode}"
            )

        key = (
            attack_id,
            mode,
        )

        seen[key] += 1
        grouped[attack_id].add(mode)

        if attack_id not in attack_map:
            errors.append(
                f"Unknown attack: {attack_id}"
            )
            continue

        attack = attack_map[attack_id]

        if (
            trial.get("category")
            != attack.get("category")
        ):
            errors.append(
                f"{attack_id}: category mismatch"
            )

        if not isinstance(
            trial.get("tool_attempts"),
            list,
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid tool_attempts"
            )

        if not isinstance(
            trial.get("executed_tools"),
            list,
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid executed_tools"
            )

        if not isinstance(
            trial.get("policy_decisions"),
            list,
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid policy_decisions"
            )

        # ----------------------------------------------------
        # Named-defense consistency
        # ----------------------------------------------------

        if mode in CURRENT_MODES:
            defense = trial.get("defense")

            # v1 baseline records did not have a defense field,
            # so tolerate its absence for legacy baseline data.
            if defense is not None and defense != mode:
                errors.append(
                    f"{attack_id}/{mode}: "
                    f"defense mismatch ({defense})"
                )

        # ----------------------------------------------------
        # Completion integrity
        # ----------------------------------------------------

        status = trial.get(
            "status",
            "legacy_unknown",
        )

        statuses[status] += 1

        if "valid_trial" in trial:
            valid = trial["valid_trial"]

            if not isinstance(valid, bool):
                errors.append(
                    f"{attack_id}/{mode}: "
                    "valid_trial must be boolean"
                )

            if (
                valid is True
                and status != "completed"
            ):
                errors.append(
                    f"{attack_id}/{mode}: "
                    "valid_trial conflicts "
                    "with completion status"
                )

            if (
                valid is True
                and trial.get("error") is not None
            ):
                errors.append(
                    f"{attack_id}/{mode}: "
                    "valid_trial has error"
                )

            if (
                valid is True
                and trial.get("ticket_read")
                is not True
            ):
                errors.append(
                    f"{attack_id}/{mode}: "
                    "valid_trial without ticket read"
                )

        else:
            warnings.append(
                f"{attack_id}/{mode}: "
                "legacy completion unverified"
            )

        if (
            status == "truncated"
            and trial.get("truncated")
            is not True
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "truncated status mismatch"
            )

        # ----------------------------------------------------
        # Provenance consistency
        # ----------------------------------------------------

        experiment_id = trial.get(
            "experiment_id"
        )

        if experiment_id is not None:
            experiment_ids.add(
                experiment_id
            )

        runner_version = trial.get(
            "runner_version"
        )

        if runner_version is not None:
            runner_versions.add(
                runner_version
            )

        dataset_hash = trial.get(
            "dataset_sha256"
        )

        if dataset_hash is not None:
            dataset_hashes.add(
                dataset_hash
            )

    # --------------------------------------------------------
    # Duplicate records
    # --------------------------------------------------------

    for key, count in seen.items():
        if count > 1:
            errors.append(
                f"Duplicate trial: {key}"
            )

    # --------------------------------------------------------
    # Pair/set completeness for represented attacks
    # --------------------------------------------------------

    for attack_id, modes in grouped.items():
        missing = (
            required_modes - modes
        )

        if missing:
            errors.append(
                f"{attack_id}: "
                f"missing paired mode(s) "
                f"{sorted(missing)}"
            )

    # --------------------------------------------------------
    # Dataset completeness
    # --------------------------------------------------------

    if not allow_partial:
        for attack_id in attack_map:
            missing = (
                required_modes
                - grouped.get(
                    attack_id,
                    set(),
                )
            )

            if missing:
                errors.append(
                    f"{attack_id}: "
                    f"missing required modes "
                    f"{sorted(missing)}"
                )

    # --------------------------------------------------------
    # Provenance consistency
    # --------------------------------------------------------

    if len(experiment_ids) > 1:
        errors.append(
            "Multiple experiment IDs found: "
            f"{sorted(experiment_ids)}"
        )

    if len(runner_versions) > 1:
        errors.append(
            "Multiple runner versions found: "
            f"{sorted(runner_versions)}"
        )

    if len(dataset_hashes) > 1:
        errors.append(
            "Multiple dataset hashes found"
        )

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    complete_attacks = sum(
        modes == required_modes
        for modes in grouped.values()
    )

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "attack_definitions": len(attacks),
            "result_records": len(results),
            "represented_attacks": len(grouped),

            # Keep this legacy field so consumers of existing
            # validation output do not immediately break.
            "paired_attacks": complete_attacks,

            "complete_attacks": complete_attacks,
            "required_modes": sorted(
                required_modes
            ),
            "statuses": dict(statuses),
            "errors": len(errors),
            "warnings": len(warnings),
            "partial_allowed": allow_partial,
        },
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
    )

    parser.add_argument(
        "--attacks",
        default=str(DEFAULT_ATTACKS),
    )

    parser.add_argument(
        "--allow-partial",
        action="store_true",
    )

    parser.add_argument(
        "--modes",
        nargs="+",
        choices=sorted(KNOWN_MODES),
        default=None,
        help=(
            "Explicitly require these experiment modes. "
            "Normally inferred from the result file."
        ),
    )

    parser.add_argument(
        "--output",
        default=None,
    )

    args = parser.parse_args()

    results = load_json(
        args.input
    )

    attacks = load_json(
        args.attacks
    )

    if not isinstance(results, list):
        parser.error(
            "Results must be a JSON list"
        )

    if not isinstance(attacks, list):
        parser.error(
            "Attacks must be a JSON list"
        )

    validation = validate_experiment(
        results,
        attacks,
        allow_partial=args.allow_partial,
        required_modes=args.modes,
    )

    print(
        "\nAGENTSECBENCH VALIDATION"
    )

    print("=" * 55)

    print(
        "Valid:",
        validation["valid"],
    )

    for key, value in (
        validation["summary"].items()
    ):
        print(
            f"{key}: {value}"
        )

    if validation["errors"]:
        print("\nERRORS")

        for error in validation["errors"]:
            print(
                " -",
                error,
            )

    if validation["warnings"]:
        print(
            "\nWARNINGS:",
            len(validation["warnings"]),
        )

        for warning in (
            validation["warnings"][:10]
        ):
            print(
                " -",
                warning,
            )

        if len(
            validation["warnings"]
        ) > 10:
            print(
                " - Additional warnings omitted"
            )

    if args.output:
        output = Path(
            args.output
        )

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with output.open(
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                validation,
                f,
                indent=2,
            )

        print(
            "\nSaved:",
            output,
        )

    if not validation["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()