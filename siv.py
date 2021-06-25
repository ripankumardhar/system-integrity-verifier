#!/usr/bin/python3
import sys
import os # For working with files and directories in an operating system
import argparse # Extracting system arguments
import hashlib # Encrypting with hash function
import pwd  # check current working directory
import json # Working with json format
from datetime import datetime # Working with date and time
from grp import getgrgid # grp library in Python gives access to the Unix group database
print("Simple SIV program implemented by Ripan which is writen in Python.\n")

# In help mode, the program will show usage and then terminates
if sys.argv[1] == "-h":
    print("* * Help mode * *")
    print("Usage of this program is as following:\n")
    print("python3 siv.py <-i|-v> -D <monitored_directory> -V <verification_file> -R <report_file> -H <hash_function>")
    sys.exit()

# argparse library is used for getting and ordering command line arguments.
parser = argparse.ArgumentParser()

arg_group = parser.add_mutually_exclusive_group()

arg_group.add_argument("-i", "--initialize", action="store_true", help="Initialization mode") # -i indicating initialization mode

arg_group.add_argument("-v", "--verify", action="store_true", help="Verification mode") # -v indicating verification mode

parser.add_argument("-D", "--monitored_directory", type=str, help="Write the name of the directory you want to monitor") # -D inidicating monitored_directory

parser.add_argument("-V", "--verification_file", type=str,help="Write the name of Verification File that can store information of directories & files in the monitored directory") # -V indicating verification file directory

parser.add_argument("-R", "--report_file", type=str, help="Write the name of the Report File to store final report") # -R indicating the name of report file directory

parser.add_argument("-H", "--hash_function", type=str, help="Write name of the hash function, supported hashes are 'SHA-1' and 'MD-5'") # -H indicating type of hash function


args = parser.parse_args()

# Defining parameters to simplify
_monitor_dir = args.monitored_directory             # Directory to be monitored
_verification_file_path = args.verification_file    # Path of the verification file
_report_file_path = args.report_file                # Path of the report file
_hash = args.hash_function                          # Name of the hash function which will be used for message digest
startTime = 0                                       # Defining this variable to count time






#...........................................................
# initialization mode ......................................
#...........................................................





if args.initialize: # Initialization mode

    print("Initialization Mode\n")

    # Check if monitored directory exists
    if os.path.isdir(_monitor_dir) == 1:
        print(f"{_monitor_dir} Directory is available...")

        if (_hash == "sha1" or _hash == "sha-1" or _hash == "SHA1" or _hash == "SHA-1"):
            _hash = "SHA-1"

        if (_hash == "md5" or _hash == "md-5" or _hash == "MD5" or _hash == "MD-5"):
            _hash = "MD-5"

        # Check the algorithm requested for hashing
        if _hash == "SHA-1" or _hash == "MD-5":

            f = 0
            d = 0
            my_directory = [] # define directory as a list to append easily
            in_file = {} # define file as a dictionary
            in_hash = {} # define hash as a dictionary
            in_dir = {} # define directory as dictionary


            # Check if Verification file and Report file are outside monitored directory
            if (os.path.commonprefix([_monitor_dir, _verification_file_path]) == _monitor_dir) or (os.path.commonprefix([_monitor_dir, _report_file_path]) == _monitor_dir):
                print("Verification and Report file must be outside of the monitored directory\n")
                sys.exit()

            else:
                print("Verification file and Report file are outside monitored directory \n")


            # Ask user whether to overwrite Verification file.
            # If yes, then proceed. If no or invalid input then exit.
            if(os.path.isfile(_verification_file_path)):
                user_choice = input ("Would you like to overwrite verification file? yes/no: ")

                if user_choice == "no": # If input == no, exit the system
                    print("You choose not to overwrite verification file. Program terminate.")
                    sys.exit()

                elif user_choice == "yes":
                    print("Verification file will be overwriten.")

                else:
                    print("Invalid input, please write only 'yes' or 'no'")
                    sys.exit()
            else:
                os.open(_verification_file_path, os.O_CREAT, mode=0o777)
                print("Verification file was not available but created now.")


            # Ask user whether to overwrite Report file.
            # If yes, then proceed. If no or invalid input then exit.
            if(os.path.isfile(_report_file_path)):
                user_choice = input ("Would you like to overwrite Report file? yes/no: ")

                if user_choice == "no": # If input == no, exit the system
                    print("You choose not to overwrite Report file. Program terminates.")
                    sys.exit()

                elif user_choice == "yes":
                    print("Report file will be overwriten.")

                else:
                    print("Invalid input, please write only 'yes' or 'no'")
                    sys.exit()

            else:
                os.open(_report_file_path, os.O_CREAT, mode=0o777)
                print("Report file was not available but created now.")


            startTime = datetime.utcnow()

            # Goes inside the monitored directory with a for loop
            for sub_dir, dirs, files in os.walk(_monitor_dir):


                # to record any file and folders in it.
                for i in dirs:

                    f += 1
                    path = os.path.join(sub_dir, i)
                    modification_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c') # To get last modification time of the file
                    access = oct(os.stat(path).st_mode & 0o777) # octal value of 0o777 is equal to chmod 511
                    size = os.path.getsize(path) # To get the the size of the file
                    user = pwd.getpwuid(os.stat(path).st_uid).pw_name # To get the directory of the file
                    group = getgrgid(os.stat(path).st_gid).gr_name # Name of the group this file belongs to

                    # Saving the Values in a variable (in_dir)
                    in_dir[path] = {"Last Modification Time": modification_time, "Accessibility": access, "Size": size, "User": user, "Group":group}


                for file in files: # Goes inside the file in monitored directory to record the following values.

                    d += 1
                    temp_path = os.path.join(sub_dir, file)
                    temp_modification_time = datetime.fromtimestamp(os.stat(temp_path).st_mtime).strftime('%c') # Record initialization time and date
                    temp_access = oct(os.stat(temp_path).st_mode & 0o777) # octal value of 0o777 is equal to chmod 511
                    temp_size = os.stat(temp_path).st_size
                    temp_user = pwd.getpwuid(os.stat(temp_path).st_uid).pw_name
                    temp_group = getgrgid(os.stat(temp_path).st_gid).gr_name

                    # Message digest with MD-5
                    if _hash == "MD-5":
                        hash_type = "md5"
                        in_hash = {"hash_type": hash_type}
                        h = hashlib.md5()
                        with open(temp_path, 'rb') as myfile: # Open the file for reading only in binary mode
                            buffer = myfile.read()
                            h.update(buffer)
                            message_digest = h.hexdigest() # Containing only hexadecimal digits.

                    # Message digest with SHA-1
                    elif _hash == "SHA-1":
                        hash_type = "sha1"
                        in_hash = {"hash_type": hash_type}
                        h = hashlib.sha1()
                        with open(temp_path, 'rb') as myfile: # Open the file for reading only in binary mode
                            buffer = myfile.read()
                            h.update(buffer)
                            message_digest = h.hexdigest()

                    # Save the Key:Values in a dictionary (in_file)
                    in_file[temp_path] = {"Last Modification Time": temp_modification_time , "Accessibility": temp_access, "Size": temp_size, "User": temp_user, "Group": temp_group, "hash_type": message_digest}

            my_directory.append(in_dir)
            my_directory.append(in_file)
            my_directory.append(in_hash)
            json_string = json.dumps(my_directory, indent=4, sort_keys=True)


            # Write into Verification file
            with open(_verification_file_path, "w") as writefile:
                writefile.write(json_string)

            print("\nVerification file has been created")

            # calculating total time taken for initialization
            total_time_taken = datetime.utcnow() - startTime
            print (f"\nTotal time taken for initialization: {total_time_taken}")

            # Write into Report file
            with open(_report_file_path, "w") as writefile:
                writefile.write("-" * 46)
                writefile.write("\n******* Reports of initialization mode *******\n")
                writefile.write("-" * 46)
                writefile.write(f"\nMonitored directory >>          {_monitor_dir}")
                writefile.write(f"\nVerification file path >>       {_verification_file_path}")
                writefile.write(f"\nReport file path >>             {_report_file_path}")
                writefile.write("\nNumber of directories parsed >> "+ str(f))
                writefile.write("\nNumber of files parsed >>       "+ str(d))
                writefile.write("\nTime taken >>                   "+ str(total_time_taken) + "\n")


            print("\nReport File has been created")

        else:
            print("Hash function is not supported. Only 'MD-5' and 'SHA-1' are supported.")
            sys.exit()

    else:
        print("Monitored directory does NOT exist.")
        sys.exit()







#....................................................
# Verification Mode .................................
#....................................................






elif args.verify:

    print("Verification Mode\n")


    if os.path.isfile(_verification_file_path) == 1: # Return true if verification file is created.
        print("Verification File is available\n")

        # Check if Verification and Report files are outside monitored directory
        if (os.path.commonprefix([_monitor_dir, _verification_file_path]) == _monitor_dir) or (os.path.commonprefix([_monitor_dir, _report_file_path]) == _monitor_dir):
            print("Verification and Report file must be outside monitor directory...\n")
            sys.exit()

        else:
            print("Verification and Report files are outside monitored directory\n")

    else:
        print("Verification file is not available")
        sys.exit()

    # Ask user whether to overwrite Report file.
    # If yes, then proceed. If no or invalid input then exit.
    if(os.path.isfile(_report_file_path)):
        user_choice = input ("Would you like to overwrite Report file? yes/no: ")

        if user_choice == "no": # If input == no, exit the system
            print("You choose not to overwrite Report file. Program terminates.")
            sys.exit()

        elif user_choice == "yes":
            print("Report file will be overwriten.")

        else:
            print("Invalid input, please write only 'yes' or 'no'")
            sys.exit()

    else:
        os.open(_report_file_path, os.O_CREAT, mode=0o777)
        print("Report file was not available but created now.")

    startTime = datetime.utcnow() # Start counting time for verification.
    f = 0  # Number of directories parsed.
    d = 0  # Number of files parsed.
    k = 0  # Number of warnings for monitored directories and files.

    with open(_verification_file_path) as input_file:
        json_decode = json.load(input_file)


    hash_type = json_decode[2]['hash_type']


    report_write = open(_report_file_path, "a")

    for sub_dir, dirs, files in os.walk(_monitor_dir):
        # The following information extracted from the monitored directory.
        for fds in dirs:
            f += 1
            path = os.path.join(sub_dir, fds)
            size = os.stat(path).st_size
            user = pwd.getpwuid(os.stat(path).st_uid).pw_name
            group = getgrgid(os.stat(path).st_gid).gr_name
            modification_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')
            access = oct(os.stat(path).st_mode & 0o777)

            print(f"Directory >> {path}\n")

            if path in json_decode[0]: # [0] index means path, [1] means file, [2] means folder.

                # CheckING the size compared to initial one.
                if size != json_decode[0][path]['Size']:
                    report_write.write(f"...WARNING... Directory {path} has a different size\n")
                    k = k+1

                # Checking the user
                if user != json_decode[0][path]['User']:
                    report_write.write(f"\n...WARNING... Directory {path} has a different user \n")
                    k = k+1

                # Checking the group compared to initial one.
                if group != json_decode[0][path]['Group']:
                    report_write.write(f"\n...WARNING... Directory {path} has a different group\n")
                    k = k+1

                # Checking the modification_time compared to initial one.
                if modification_time != json_decode[0][path]['Last Modification Time']:
                    report_write.write(f"\n...WARNING... Directory {path} has a different modification date\n")
                    k = k+1

                # Checking the access compare to initial one.
                if access != json_decode[0][path]['Accessibility']:
                    report_write.write(f"\n...WARNING... Directory {path} has changed the access permission\n")
                    k = k+1
            else:
                report_write.write(f"\n...WARNING... Directory {path} has been added\n")
                k = k+1

    # check if any file or folder removed from the monitored path.
    for each_prev_dir in json_decode[0]:

        if os.path.isdir(each_prev_dir) == 0:
            report_write.write(f"\n...WARNING... Directory {each_prev_dir} has been removed\n")
            k = k+1

    for sub_dir, dirs, files in os.walk(_monitor_dir): # Travercing in monitored directory to see using DFS.
        for file in files:
            d += 1
            temp_path = os.path.join(sub_dir, file)
            temp_size = os.stat(temp_path).st_size
            temp_user = pwd.getpwuid(os.stat(temp_path).st_uid).pw_name
            temp_group = getgrgid(os.stat(temp_path).st_gid).gr_name
            temp_modification_time = datetime.fromtimestamp(os.stat(temp_path).st_mtime).strftime('%c')
            temp_access = oct(os.stat(temp_path).st_mode & 0o777)

            # Writen for debugging purpose
            #print(f" ----- File ----- {temp_path}    is recorded successfully ...")

            # Message digest computed with MD-5
            if hash_type == "md5":
                #print(hash_type)   # Writen for debugging purpose
                h = hashlib.md5()
                with open(temp_path, 'rb') as mfile:
                    buffer = mfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()


            # Message digest computed with SHA-1
            elif hash_type == "sha1":
                #print(hash_type)   # Writen for debugging purpose
                h = hashlib.sha1()
                with open(temp_path, 'rb') as hfile:
                    buffer = hfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()

            if temp_path in json_decode[1]: # Index [1] means file.

                # Check if size is changed compared to initial one.
                if temp_size != json_decode[1][temp_path]['Size']:
                    report_write.write(f"\n...WARNING... File {temp_path} is changed in size\n")
                    k += 1

                 # Check if user is changed compared to initial one.
                if temp_user != json_decode[1][temp_path]['User']:
                    report_write.write(f"\n...WARNING... File {temp_path} has a different user\n")
                    k += 1

                # Check if group is changed compared to initial one.
                if temp_group != json_decode[1][temp_path]['Group']:
                    report_write.write(f"\n...WARNING... File {temp_path} has a different group\n")
                    k += 1

                # Check if modification time is changed compared to initial one.
                if temp_modification_time != json_decode[1][temp_path]['Last Modification Time']:
                    report_write.write(f"\n...WARNING... File {temp_path} has a different modification date or time\n")
                    k += 1

                # Check if access is changed compared to initial one.
                if temp_access != json_decode[1][temp_path]['Accessibility']:
                    report_write.write(f"\n...WARNING... File {temp_path} has modified accessibility permission\n")
                    k += 1

                # Check if encryption methode is changed compared to initial one.
                if message_digest != json_decode[1][temp_path]['hash_type']:
                    report_write.write(f"\n...WARNING... File {temp_path} has a change in its content\n")
                    k += 1
            else:
                report_write.write(f"\n...WARNING... File {temp_path} has been added\n")
                k += 1

    for each_prev_file in json_decode[1]:
        if os.path.isfile(each_prev_file) == 0: # Return false if file is not available or may removed.
            report_write.write("\n...WARNING... File " + each_prev_file + " has been deleted\n")
            k += 1

    # calculating total time taken for verification
    total_time_taken = datetime.utcnow() - startTime
    print (f"\nTotal time taken for verification: {total_time_taken}")

    # The Following information is extracted and write in report file.
    report_write.write("\n" + "-" * 44)
    report_write.write("\n******* Reports of verification mode ******* \n")
    report_write.write("-" * 44)
    report_write.write(f"\nMonitored directory >>           {_monitor_dir}")
    report_write.write(f"\nVerification File >>             {_verification_file_path}")
    report_write.write(f"\nReport File >>                   {_report_file_path}")
    report_write.write("\nNumber of directories parsed >>  " + str(f))
    report_write.write("\nNumber of files parsed >>        " + str(d))
    report_write.write("\nTime taken >>                    " + str(total_time_taken))
    report_write.write("\nTotal Warnings >>                " + str(k))
    report_write.close()

    print("\nVerification report saved in the report file.")
    print(f"\nTotally {f} directories and {d} files were handled.\n")
