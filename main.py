from evaluation.runner import run_all_attacks

import json
from pathlib import Path
from datetime import datetime


TRIALS_PER_ATTACK = 3

results = run_all_attacks(
    trials_per_attack=TRIALS_PER_ATTACK
)
# Print individual attack trial results
for result in results:
    print("\n==============================")
    print(result["attack_id"])
    print(result["name"])
    print(f"Trial: {result['trial']}")
    print("==============================")

    print("\nAGENT RESPONSE:")
    print(result["agent_response"])

    print("\nAUDIT LOG:")
    for entry in result["audit_log"]:
        print(entry)

    print("\nPOLICY LOG:")
    for entry in result["policy_log"]:
        print(entry)

    print("\nEVALUATION:")
    print(result["evaluation"])


# Calculate overall benchmark statistics

# Get all unique attack IDs
unique_attack_ids = {
    result["attack_id"]
    for result in results
}

total_attacks = len(unique_attack_ids)
total_trials = len(results)

successful_trials = sum(
    1
    for result in results
    if result["evaluation"]["attack_success"]
)

blocked_attempt_trials = sum(
    1
    for result in results
    if result["evaluation"]["blocked_attack_attempt"]
)

attack_success_rate = (
    successful_trials / total_trials * 100
    if total_trials > 0
    else 0
)

blocked_attempt_rate = (
    blocked_attempt_trials / total_trials * 100
    if total_trials > 0
    else 0
)


# Print benchmark summary
print("\n==============================")
print("BENCHMARK SUMMARY")
print("==============================")

print(f"Unique attacks: {total_attacks}")
print(f"Trials per attack: {TRIALS_PER_ATTACK}")
print(f"Total trials: {total_trials}")
print(f"Successful trials: {successful_trials}")
print(f"Attack success rate: {attack_success_rate:.1f}%")
print(f"Blocked attempt trials: {blocked_attempt_trials}")
print(f"Blocked attempt rate: {blocked_attempt_rate:.1f}%")


# Calculate results by attack category
categories = {}

for result in results:
    category = result["category"]

    if category not in categories:
        categories[category] = {
            "total_trials": 0,
            "successful_trials": 0
        }

    categories[category]["total_trials"] += 1

    if result["evaluation"]["attack_success"]:
        categories[category]["successful_trials"] += 1


# Print category results
print("\n==============================")
print("RESULTS BY CATEGORY")
print("==============================")

for category, data in categories.items():

    success_rate = (
        data["successful_trials"]
        / data["total_trials"]
        * 100
        if data["total_trials"] > 0
        else 0
    )

    print(
        f"{category}: "
        f"{data['successful_trials']}/"
        f"{data['total_trials']} successful trials "
        f"({success_rate:.1f}%)"
    )


# Build complete benchmark output
benchmark_output = {
    "model": "qwen3:4b-instruct",
    "defense": "tool_authorization_policy",
    "trials_per_attack": TRIALS_PER_ATTACK,
    "unique_attacks": total_attacks,
    "total_trials": total_trials,
    "successful_trials": successful_trials,
    "attack_success_rate": attack_success_rate,
    "blocked_attempt_trials": blocked_attempt_trials,
    "blocked_attempt_rate": blocked_attempt_rate,
    "category_results": categories,
    "results": results
}


# Create results directory
BASE_DIR = Path(__file__).resolve().parent

results_directory = BASE_DIR / "results"
results_directory.mkdir(exist_ok=True)


# Create unique filename using current date and time
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

output_path = (
    results_directory
    / f"defended_{timestamp}.json"
)

# Save benchmark results
with open(output_path, "w", encoding="utf-8") as file:
    json.dump(
        benchmark_output,
        file,
        indent=2
    )


print(f"\nResults saved to: {output_path}")