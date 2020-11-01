import os
import test_settings

def run_test():
    runs = (
        "python2 {} --profile={} -f {} escalate -n cmd.exe"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
        "python2 {} --profile={} -f {} escalate -i 1604"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
    )
    try:
        for run in runs:
            os.system(run)
            
    except Exception:
        print("Failure")

run_test()
