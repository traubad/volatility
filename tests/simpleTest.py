import os
import test_settings

def run_test():
    runs = (
        ["python2 {} --profile={} -f {} escalate -n explorer.exe --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
            "Check -n flag with a single process name"],
        ["python2 {} --profile={} -f {} escalate -i 1812 --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
            "Check -i flag with a single pid"],
        ["python2 {} --profile={} -f {} escalate -n explorer.exe,TrueCrypt.exe --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
            "Check -n flag with 2 process names"],
        ["python2 {} --profile={} -f {} escalate -i 1812,956 --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
            "Check -i flag with a single pid"],
        ["python2 {} --profile={} -f {} escalate -a --write"
            .format(test_settings.vol_path, test_settings.profile, test_settings.mem),
            "Check -a flag"],
    )
    try:
        print("\n")
        for i, [run, text] in enumerate(runs):
            print("Test {}:".format(i+1))
            print("\t{}\n".format(text))
            os.system('echo "Yes, I want to enable write support" | '+run)
            os.system('echo "\n"')
            print("Success\n\n{}\n".format("-"*75))

    except Exception:
        print("Failure")

run_test()
