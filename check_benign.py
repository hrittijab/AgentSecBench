from evaluation.benign_runner import run_all_benign_cases


results = run_all_benign_cases()

for result in results:
    print("\n==============================")
    print(result["case_id"])
    print(result["name"])
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

total_cases = len(results)

successful_cases = sum(
    1
    for result in results
    if result["evaluation"]["benign_success"]
)

benign_success_rate = (
    successful_cases / total_cases * 100
    if total_cases > 0
    else 0
)

print("\n==============================")
print("BENIGN BENCHMARK SUMMARY")
print("==============================")

print(f"Total benign cases: {total_cases}")
print(f"Successful cases: {successful_cases}")
print(
    f"Benign task success rate: "
    f"{benign_success_rate:.1f}%"
)