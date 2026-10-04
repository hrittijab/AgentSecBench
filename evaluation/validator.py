
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ATTACKS = (
    ROOT / "attacks" / "generated_attacks.json"
)

EXPECTED_MODES = {"baseline", "defended"}


def load_json(path):
    with Path(path).open(
        encoding="utf-8"
    ) as f:
        return json.load(f)


def validate_experiment(
    results,
    attacks,
    allow_partial=False
):
    """
    Validate benchmark integrity.

    Checks:
    - duplicate trial records
    - missing baseline/defended pairs
    - unknown attack IDs
    - category mismatches
    - malformed execution records
    - missing or inconsistent metadata

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

    seen = Counter()
    grouped = defaultdict(set)
    statuses = Counter()

    for index, trial in enumerate(results):
        attack_id = trial.get("attack_id")
        mode = trial.get("mode")

        if not attack_id:
            errors.append(
                f"Trial {index}: missing attack_id"
            )
            continue

        if mode not in EXPECTED_MODES:
            errors.append(
                f"{attack_id}: invalid mode {mode}"
            )
            continue

        key = (attack_id, mode)
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
            trial.get("tool_attempts"), list
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid tool_attempts"
            )

        if not isinstance(
            trial.get("executed_tools"), list
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid executed_tools"
            )

        if not isinstance(
            trial.get("policy_decisions"), list
        ):
            errors.append(
                f"{attack_id}/{mode}: "
                "invalid policy_decisions"
            )

        status = trial.get(
            "status", "legacy_unknown"
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

    for key, count in seen.items():
        if count > 1:
            errors.append(
                f"Duplicate trial: {key}"
            )

    for attack_id, modes in grouped.items():
        missing = EXPECTED_MODES - modes

        if missing:
            errors.append(
                f"{attack_id}: "
                f"missing paired mode(s) "
                f"{sorted(missing)}"
            )

    if not allow_partial:
        for attack_id in attack_map:
            missing = (
                EXPECTED_MODES
                - grouped.get(attack_id, set())
            )

            if missing:
                errors.append(
                    f"{attack_id}: "
                    f"missing required modes "
                    f"{sorted(missing)}"
                )

    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "attack_definitions": len(attacks),
            "result_records": len(results),
            "represented_attacks": len(grouped),
            "paired_attacks": sum(
                modes == EXPECTED_MODES
                for modes in grouped.values()
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
        required=True
    )

    parser.add_argument(
        "--attacks",
        default=str(DEFAULT_ATTACKS)
    )

    parser.add_argument(
        "--allow-partial",
        action="store_true"
    )

    parser.add_argument(
        "--output",
        default=None
    )

    args = parser.parse_args()

    results = load_json(args.input)
    attacks = load_json(args.attacks)

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
        allow_partial=args.allow_partial
    )

    print("\nAGENTSECBENCH VALIDATION")
    print("=" * 55)

    print(
        "Valid:",
        validation["valid"]
    )

    for key, value in (
        validation["summary"].items()
    ):
        print(f"{key}: {value}")

    if validation["errors"]:
        print("\nERRORS")

        for error in validation["errors"]:
            print(" -", error)

    if validation["warnings"]:
        print(
            "\nWARNINGS:",
            len(validation["warnings"])
        )

        for warning in (
            validation["warnings"][:10]
        ):
            print(" -", warning)

        if len(validation["warnings"]) > 10:
            print(
                " - Additional warnings omitted"
            )

    if args.output:
        output = Path(args.output)
        output.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with output.open(
            "w", encoding="utf-8"
        ) as f:
            json.dump(
                validation,
                f,
                indent=2
            )

        print(
            "\nSaved:",
            output
        )

    if not validation["valid"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
