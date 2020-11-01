import os
import test_settings

def run_test():
    runs = (
        "python2 {} --profile={} -f {} escalate -n explorer.exe --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
        "python2 {} --profile={} -f {} escalate -i 1812 --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
    )
    try:
        for run in runs:
            os.system('echo "Yes, I want to enable write support" | '+run)
            os.system('echo "\n\n"')

    except Exception:
        print("Failure")

run_test()
