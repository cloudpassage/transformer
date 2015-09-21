transformer
===========

Convert between AWS Security Groups and Halo Firewall Policies

This document describes the CloudPassage Transformer and explains how you can configure the script to migrate between AWS Security Groups and Halo firewall policies.

##Prerequisites
To get started, you must have the following privileges and software resources:
* An active CloudPassage Halo subscription. If you don't have one, Register for CloudPassage to receive your credentials and further instructions by email.
* Access to your CloudPassage API key. Best practice is to create a new read-only key specifically for use with this script.
* Python 2.6 or later. You can download Python from http://www.python.org/getit/
* Boto 2.1.0 or later. You can download Boto from http://code.google.com/p/boto/downloads/list
* Access to Amazon’s AWS service account. See http://aws.amazon.com for instructions on how to sign up for an Amazon AWS account.
* The Transformer scripts (transformSGToHaloFP.py and transformHaloFPToSG.py) and its associated files.


Note:  The Transformer makes calls to the CloudPassage Firewall API, which is available to all Halo subscribers at all levels (including Basic). Many other parts of the CloudPassage API are available only to Halo users with a NetSec or Professional subscription; if you want to use those parts of the API, you can upgrade your subscription on the Manage Subscription page of the Halo Portal.

##How the Transformer Works
The purpose of the Halo Transformer script is to transform between AWS Security Group and CloudPassage Halo firewall policies. The Transformer is a Python script that is designed to iterate through AWS regions and migrate AWS Security Groups into Halo firewall policies. It will also iterate through the Halo Firewall Policies in your Halo account and translate them into AWS Security Groups:

* The script can transform both EC2-classic and EC2-VPC security groups.
Since EC2-classic SG only supports inbound rules, the corresponding Halo firewall policy will allow all outbound connections. 

* To resolve any naming conflicts in Halo firewall policies, the script qualifies the firewall policy name by prefixing it with information about the source SG. For example, if the SG being transformed is an EC2 VPC group from the us-east-1 region, the prefix used will be ‘us-east-1-vpc’.
There are multiple command line options available that enable you to customize the transformation process

* You can ask the script to transform a single Security Group, an entire AWS regions’ Security Group or Security Groups across all available AWS regions.
* You can override the prefix the script chooses by using the --destprefix command line option.
_Command line arguments._ You can execute the Transform script with a command like this:
```
$ transforSGToHaloFP.py arguments
```

To view the set of supported command-line arguments, launch the script with the argument -? or -h to view the usage page. These are the arguments:

Print the usage page.
```
-?
```

Full pathname to the file that holds the Halo API key info. 
```
--auth=filename
```

Specify an AWS region to convert all Security Groups in that region.
```
--region=<name>
```

Iterates through all AWS regions, to have their Security Groups converted.
```
--allregions
```

If converting a single Security Group, you can specify name of destination Halo firewall policy.
```
--dest=<name>
```

When converting all Security Groups across, or within a region, add specified prefix to name of each Halo firewall policy.
```
--destprefix=<string>
```

Sets target platform for Halo firewall policy. Can be 'linux', 'windows', or 'all'.
```
--platform=<name>
```

_Authentication to the Halo API._ Halo requires the Transformer to pass both the key ID and secret key values for a valid Halo API key in order to obtain the event data. You pass those values in a file named by default transform.auth, located in the same directory as transform.py and its associated script files. The format for the file is described in Section A.

Alternatively, you can pass those values in a different file by specifying the full path to the file in the --auth=filename option. 

_Platform support._ The Transformer runs on both Linux and Windows operating systems.

###A. Retrieve and Save your CloudPassage API Key
The Transformer retrieves events from your CloudPassage Halo account by making calls to the CloudPassage API. The API requires the script to authenticate itself during every session; therefore, you need to make your CloudPassage API Key available to the script. 

To retrieve your CloudPassage API key, log into the CloudPassage Portal and navigate to Settings > Site Administration and click the API Keys tab. (If you haven’t generated an API key yet, do so by clicking Add New Key.)

Since we are going to be adding firewall policies to your Halo account, if you do create an API key, the key has to have write permissions on the Halo account.


You will need to retrieve both the Key ID and the Secret Key values for the API key. Click Show for your key on the API Keys tab to display both values.

Copy the ID and the secret into a text file so that it contains just one line, with the key ID and the secret separated by a vertical bar ("|"):
```
your_key_id|your_secret_key
```

Save the file as convert.auth (or any other name, if you will be using the --auth command option). You will need this authentication file to run the Transformer (in Section B and Section C).

###B. Retrieve and Save your Amazon AWS Credentials

Store your AWS credentials in the boto configuration file 

If boto doesn’t get credentials passed to it explicitly and it doesn’t find them in the user’s environment, it will try to find them in the boto configuration files. By default, boto will look for configuration information in /etc/boto.cfg and in ~/.boto. If you want to store your config info elsewhere, you can set the environment variable BOTO_CONFIG to the path to the config file and boto will read it from there. To add your credentials to the botoconfig file, you would add a section like this:

[Credentials]
aws_access_key_id = your_access_key 
aws_secret_access_key = your_secret_key

Once the credentials are stored in the boto config file, boto will use them automatically each time you use it. This is the most convenient way to deal with your AWS credentials. However, if you store your AWS credentials in your boto config file, you should set the file protections such that the file is readable only by you.

###C. Test the Transformer
We recommend that you execute the Transformer script first, to get familiar with the different input switches and output filenames it supports. Then you can choose the options that best suit your needs.

Place all of the script-related files in the same directory. That is:
* transformer.py
* transformSGToHaloFP.py
* transformHaloFPToSG.py
* cpapi.py, cputils.py and cpfw_convert.py
* transform.auth (unless you will use the --auth command option, in which case the authentication file can be anywhere, and can be named anything.)

Set environment variables as necessary:

On Linux:
Include the full path to the Python interpreter  in the PATH environment variable.

Launch the Converter from that directory, with a command like this: 
```
$ transformSGToHaloFP.py --region=us-east-1
```
or
```
$ transformHaloFPToSG.py
```


<!---
#CPTAGS:partner-integration integration automation
#TBICON:images/ruby_icon.png
-->
