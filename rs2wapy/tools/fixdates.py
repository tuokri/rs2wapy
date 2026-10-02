# Copyright (c) 2026 Tuomo Kriikkula
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import datetime
import os
import subprocess
from email.utils import format_datetime
from email.utils import parsedate_to_datetime

# localtz = pytz.timezone("Europe/Helsinki")


def fix_commits():
    try:
        env = os.environ.copy()

        start = datetime.datetime.strptime("07:00:00", "%H:%M:%S")
        stop = datetime.datetime.strptime("18:00:00", "%H:%M:%S")
        # start = localtz.localize(start)
        # stop = localtz.localize(stop)
        range_start: datetime.time = start.time()
        range_stop: datetime.time = stop.time()

        with open("commit_log.txt", encoding="utf-8") as f:
            commit_log = f.read()
        # commit_log = subprocess.check_output(
        #     ["git", "log", "--abbrev-commit"], encoding="utf-8")
        log_entries = commit_log.split("\n")

        flag = False
        commit_hash = ""
        commits = {}
        for entry in log_entries:
            if not flag and entry.startswith("commit"):
                flag = True
                commit_hash = entry.split(" ")[1]
                commits[commit_hash] = ""
            if flag and entry.startswith("Date:"):
                flag = False
                commits[commit_hash] = parsedate_to_datetime(
                    entry.split("Date:")[1].strip()
                ).astimezone()

        current_date: datetime.datetime = datetime.datetime.strptime(
            "01 01 2000", "%d %m %Y"
        ).astimezone()

        for k, v in commits.items():
            print(k, ":", v.isoformat())
        print("=" * 80)

        hour = 19
        minute = 0

        print(f"processing {len(commits)} commits...")
        for log_hash in reversed(commits):
            print("." * 80)

            status = subprocess.check_output(["git", "status"], encoding="utf-8")
            lines = status.split("\n")
            current_hash = ""
            for line in lines:
                if "Next command" in line or "No command" in line:
                    break
                try:
                    print(f"checking line: '{line}'")
                    current_hash = line.split("edit")[1].split(" ")[1]
                except IndexError:
                    pass

            print("log_hash     :", log_hash)
            print("current_hash :", current_hash)
            print("current_date :", current_date)

            prev_date = current_date
            current_date = commits[current_hash]

            if current_date.date() > prev_date.date():
                print("day changed, resetting minutes")
                minute = 0

            print(repr(range_start))
            print(repr(current_date.time()))
            print(repr(range_stop))

            assert current_hash == log_hash

            if range_start <= current_date.time() <= range_stop:
                print("date is not ok")
                new_date = current_date.replace(hour=hour, minute=minute)
                minute += 1
            else:
                print("date is ok, checking next commit...")
                subprocess.check_call(
                    [
                        "git",
                        "rebase",
                        "--continue",
                    ]
                )
                continue

            print("new_date     :", new_date)
            date_str = format_datetime(new_date)
            print("date_str     :", date_str)

            env.update(
                {
                    "GIT_COMMITTER_DATE": f"'{date_str}'",
                    "GIT_AUTHOR_DATE": f"'{date_str}'",
                }
            )

            subprocess.check_call(
                [
                    # f"GIT_COMMITTER_DATE='{date_str}'",
                    # f"GIT_AUTHOR_DATE='{date_str}'",
                    "git",
                    "commit",
                    "--amend",
                    f'--date="{date_str}"',
                    "--no-edit",
                ],
                env=env,
            )

            subprocess.check_call(
                [
                    "git",
                    "rebase",
                    "--continue",
                ]
            )

            print("." * 80)
    except Exception:
        print("aborting")
        subprocess.check_call(["git", "rebase", "--abort"])
        raise


if __name__ == "__main__":
    fix_commits()
