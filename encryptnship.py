#! /usr/bin/python3

## Name: encryptNship
## Description: This app was created to meet a requirement to ship data packets that have client side
## encryption.
## Authour: Shane Gleeson

import argparse, os, logging, configparser, sys, base64, gzip, shutil, datetime
import boto3, time, json, pathlib

from botocore.exceptions import ClientError
from botocore.client import Config
from cryptography.fernet import Fernet
from logging.handlers import RotatingFileHandler


## Main Global Settings
config_dir = "/opt/encryptnship/conf/"
sleep_delay = 10
log_level = logging.INFO
log_file = '/var/log/encryptnship/encryptnship.log'

## Global Log Settings
logging.basicConfig(
    handlers=[RotatingFileHandler(log_file, maxBytes=1000000, backupCount=10)],
    level=log_level,
    format="%(asctime)s:%(levelname)s:%(message)s"
    )
def config_reader(config_dir):
    ## Create a list to be used for dicts that contain the info from the config files
    list1 = []
    ## Find all the files that end with conf in the conf file dir that was set in __main__
    for file in [f for f in os.listdir(config_dir) if f.endswith("conf")]:
        ## Create 2 dicts because we need a dict within a dict
        config_value_dict = {}
        conf_file_to_config_value_dict = {}
        with open(os.path.join(config_dir + file), "r") as f:
            config = configparser.RawConfigParser()
            try:
                config.read_file(f)
            except Exception as e:
                logging.error(e)

        logging.debug("config to parse - {}".format(file))
        try:
            config_value_dict.update( {"log_dir" : config.get("Settings", "log_dir")})
            config_value_dict.update( {"cmk_id" : config.get("Settings","cmk_id")})
            encryption_context = json.loads(config.get("Settings","encryption_context"))
            config_value_dict.update( {"encryption_context" : encryption_context})
            config_value_dict.update( {"region" : config.get("Settings","region")})
            config_value_dict.update( {"aws_access_key_id" : config.get("Settings","aws_access_key_id")})
            config_value_dict.update( {"aws_secret_access_key" : config.get("Settings","aws_secret_access_key")})
            config_value_dict.update( {"S3_bucket" : config.get("Settings","S3_bucket")})
            config_value_dict.update( {"bucket_folder" : config.get("Settings","bucket_folder")})
            config_value_dict.update( {"SSEKMSKeyId" : config.get("Settings","SSEKMSKeyId")})

        except configparser.NoOptionError:
            logging.critical("Error: Option not parsed in configuration file {}".format(file))
            sys.exit("Error: Option not parsed in configuration file {}".format(file))
        conf_file_to_config_value_dict = {file : config_value_dict}
        list1.append(conf_file_to_config_value_dict)
    logging.debug("List read from all conf files: {}".format(list1))
    return list1

def create_data_key(cmk_id, region, encryption_context, key_spec='AES_256'):
    # I grabbed this off the internet and updated the function to contain the region variable
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """

    # Create data key
    kms_client = boto3.client(
        'kms',
        region_name=region,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
        )
    try:
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec, EncryptionContext=encryption_context)
    except ClientError as e:
        logging.error(e)
        return None, None

    # Return the encrypted and plaintext data key
    logging.debug("Key successfully generated from cmk_id: {}".format(cmk_id))
    return response['CiphertextBlob'], base64.b64encode(response['Plaintext'])

def encrypt(filename, cmk_id, region, encryption_context):
    if filename.endswith("encrypt"):
        return filename
    # I grabbed this off the internet and add the region as a function argument
    if not os.path.exists(filename) or filename == False:
        logging.error("Can't process file: does not exists or previous step returned False")
        return False
    # Read the entire file into memory
    try:
        with open(filename, 'rb') as file:
            file_contents = file.read()
    except IOError as e:
        logging.error(e)
        return False
    # Generate a data key associated with the CMK
    # The data key is used to encrypt the file. Each file can use its own
    # data key or data keys can be shared among files.
    # Specify either the CMK ID or ARN
    data_key_encrypted, data_key_plaintext = create_data_key(cmk_id, region, encryption_context)
    if data_key_encrypted is None:
        return False
    # Encrypt the file
    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(file_contents)

    # Write the encrypted data key and encrypted file contents together
    file = filename + '.encrypt'
    try:
        with open(file, 'wb') as file_encrypted:
            file_encrypted.write(len(data_key_encrypted).to_bytes(2048,
                                                                  byteorder='big'))
            file_encrypted.write(data_key_encrypted)
            file_encrypted.write(file_contents_encrypted)
    except IOError as e:
        logging.error(e)
        move_if_fail(filename)
        logging.error("Encryption failed {} was moved to failure folder".format(filename))
        return False
    logging.debug("{} successfully encrypted and outputed as {}".format(filename, file))
    return file

def compress(filename):
    if filename.endswith("gz"):
        return filename
    out_file = filename + ".gz"
    if not os.path.exists(filename):
        logging.error("path doesn't exist {}".format(filename))
        return False
    try:
        with open(filename, 'rb') as f_in:
            with gzip.open(out_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
    except Exception as e:
        logging.error(e)
        move_if_fail(filename)
        logging.error("Compression failed {} was moved to failure folder".format(filename))
        return False
    logging.debug("{} was successfully compressed and outputed as {}".format(filename, out_file))
    return out_file

def ship_S3(filename, bucketname, bucketfolder, SSEKMSKeyId):
    if not os.path.exists(filename) or filename == False:
        logging.error("Can't process file: does not exists or previous step returned False")
        return False
    s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key)
    try:
        logging.debug("SSEKMSKeyId: {}, Bucketname: {}, Folder: {}".format(SSEKMSKeyId, bucketname, bucketfolder))
        s3_client.upload_file(filename, bucketname,  bucketfolder + os.path.basename(filename), ExtraArgs={"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": SSEKMSKeyId})
    except Exception as e:
        logging.error(e)
        move_if_fail(filename)
        logging.error("S3 Ship failed {} was moved to failure folder".format(filename))
        return False
    logging.debug("{} was successfully shipped to S3".format(filename))
    logging.debug("s3 bucket: {}, bucket folder: {}, local file: {}".format(bucketname, bucketfolder, filename))
    return True

def log_dirs(root_log_dir):
    dirs =[]
    subdir = [x for x in os.listdir(path=root_log_dir)if os.path.isdir(root_log_dir+"/"+x)]
    for file in subdir:
        path = root_log_dir + "/" + file
        dirs.append(path)
    return dirs

def log_files(log_dir, delay=61):
    try:
        logs = [x for x in os.listdir(path=log_dir)if not os.path.isdir(log_dir+"/"+x) if modification_date(log_dir + x) < datetime.datetime.now() - datetime.timedelta(seconds=delay)]
    except FileNotFoundError:
        logging.critical("Log folder does not exist: {}".format(log_dir))
        sys.exit("Program Exiting: \nLog folder does not exist: {} \n ".format(log_dir))
    logging.debug("log files need to be older than: {}".format(datetime.datetime.now()-datetime.timedelta(seconds=delay)))
    logging.debug("list of logs to process: {}".format(logs))
    return logs

def cleanup(filename):
    try:
        os.remove(filename)
    except Exception as e:
        logging.error(e)
        return False
    logging.debug("{} has been deleted".format(filename))
    return True

def modification_date(filename):
    t = os.path.getmtime(filename)
    logging.debug("{} was last modified {}".format(filename,datetime.datetime.fromtimestamp(t)))
    return datetime.datetime.fromtimestamp(t)

def move_if_fail(filename):
    current_folder = pathlib.Path(filename).parent
    failure_folder = current_folder / "failure"
    pathlib.Path(failure_folder).mkdir(parents=True, exist_ok=True)
    failure_path = failure_folder / os.path.basename(filename)
    shutil.move(filename, failure_path)
    return failure_path


if __name__ == "__main__":
    logging.info("###############################################")
    logging.info("###############################################")
    logging.info("EncryptNShip is starting ...")
    logging.info("Configuration File Directory set to: {}".format(config_dir))
    while True:
        config_list = config_reader(config_dir)
        for conf_dict in config_list:
            ## Set a delay here so the app isn't as responsive
            ## this isn't necessary
            time.sleep(sleep_delay)
            for conf_file, p_info in conf_dict.items():
                ## This loop controls the parameters set in the conf files
                ## creates a list of files to ship, sets the AWS access info
                logging.debug("Configuration File: {}".format(conf_file))
                log_file_list = log_files(p_info["log_dir"])
                if len(log_file_list) > 0:
                    logging.info("Number of files to process: {}".format(len(log_file_list)))
                ## Setting global AWS values for the config
                aws_access_key_id=p_info["aws_access_key_id"]
                aws_secret_access_key=p_info["aws_secret_access_key"]
                for log_file_name in log_file_list:
                    logging.info("logfile to be processed: {}".format(log_file_name))
                    ## Make file name we're working with have the full path
                    file_original = p_info["log_dir"]+ log_file_name
                    logging.debug("logfile full path: {}".format(file_original))
                    ## Compress file, if something goes wrong don't delete the original
                    file_compressed = compress(file_original)
                    if not file_compressed == False:
                        cleanup(file_original)
                    ## Encrypt the file, if something goes wrong don't delete the original
                    file_encrypted = encrypt(file_compressed, p_info["cmk_id"], p_info["region"], p_info["encryption_context"])
                    if not file_encrypted == False:
                        cleanup(file_compressed)
                    ## Send the file to S3, if something goes wrong don't delete the encrypted file
                    ship_S3(file_encrypted, p_info["S3_bucket"], p_info["bucket_folder"], p_info["SSEKMSKeyId"])
                    if not file_compressed == False:
                        cleanup(file_encrypted)



