#!/bin/bash -x


#
#   This code was written by somckitk@amazon.com.
#   This sample code is provided on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
#

###Global Variables###
source /root/install/config.sh
TZ_LOCAL_FILE="/etc/localtime"
NTP_CONF_FILE="/etc/ntp.conf"
USR_SAP="/usr/sap"
SAPMNT="/sapmnt"
USR_SAP_DEVICE="/dev/xvdb"
SAPMNT_DEVICE="/dev/xvdc"
SWAP_DEVICE="/dev/xvdd"
USR_SAP_VOL="xvdb"
SAPMNT_VOL="xvdc"
SWAP_VOL="xvdd"
FSTAB_FILE="/etc/fstab"
DHCP="/etc/sysconfig/network/dhcp"
CLOUD_CFG="/etc/cloud/cloud.cfg"
IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4/)
HOSTS_FILE="/etc/hosts"
HOSTNAME_FILE="/etc/HOSTNAME"
NETCONFIG="/etc/sysconfig/network/config"
ETC_SVCS="/etc/services"
SAPMNT_SVCS="/sapmnt/SWPM/services"
SERVICES_FILE="/sapmnt/SWPM/services"
SAPINST="/sapmnt/SWPM/sapinst"
SW_TARGET="/sapmnt/SWPM"
REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document/ | grep -i region | awk '{ print $3 }' | sed 's/"//g' | sed 's/,//g')
MASTER_HOSTS="/sapmnt/SWPM/master_etc_hosts"
HOSTNAME=$(hostname)

if [ "$INSTALL_SAP_VERSION" == "SAP-NetWeaver-7.4" ]
then

    PRODUCT="NW_ABAP_ASCS:NW740SR2.HDB.PIHA"
    SW_TARGET="/sapmnt/SWPM"
    SAPINST="/sapmnt/SWPM/sapinst"
    SRC_INI_DIR="/root/install"
    ASCS_INI_FILE="/sapmnt/SWPM/ASCS_00_Linux_HDB.params"


else

    PRODUCT="NW_ABAP_ASCS:NW750.HDB.ABAPHA"
    SW_TARGET="/sapmnt/SWPM/NW75"
    SAPINST="/sapmnt/SWPM/NW75/sapinst"
    SRC_INI_DIR="/root/install/NW75"
    ASCS_INI_FILE="/sapmnt/SWPM/NW75/ASCS_00_Linux_HDB.params"

fi

#
###  Variables below need to be CUSTOMIZED for your environment  ###



###Functions###


set_tz() {
#set correct timezone per CF parameter input

        rm "$TZ_LOCAL_FILE"

        case "$TZ_INPUT_PARAM" in
        PT)
                TZ_ZONE_FILE="/usr/share/zoneinfo/US/Pacific"
                ;;
        CT)
                TZ_ZONE_FILE="/usr/share/zoneinfo/US/Central"
                ;;
        ET)
                TZ_ZONE_FILE="/usr/share/zoneinfo/US/Eastern"
                ;;
        *)
                TZ_ZONE_FILE="/usr/share/zoneinfo/UTC"
                ;;
        esac

        ln -s "$TZ_ZONE_FILE" "$TZ_LOCAL_FILE"

        #validate correct timezone
        CURRENT_TZ=$(date +%Z | cut -c 1,3)

        if [ "$CURRENT_TZ" == "$TZ_INPUT_PARAM" -o "$CURRENT_TZ" == "UC" ]
        then
                echo 0
        else
                echo 1
        fi
}

set_oss_configs() {

    #This section is from OSS #2205917 - SAP HANA DB: Recommended OS settings for SLES 12 / SLES for SAP Applications 12
    #and OSS #2292711 - SAP HANA DB: Recommended OS settings for SLES 12 SP1 / SLES for SAP Applications 12 SP1

    zypper remove ulimit > /dev/null


    echo "###################" >> /etc/init.d/boot.local
    echo "#BEGIN: This section inserted by AWS SAP Quickstart" >> /etc/init.d/boot.local

    #Disable THP
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/init.d/boot.local

    echo 10 > /proc/sys/vm/swappiness
    echo "echo 10 > /proc/sys/vm/swappiness" >> /etc/init.d/boot.local

    #Disable KSM
    echo 0 > /sys/kernel/mm/ksm/run
    echo "echo 0 > /sys/kernel/mm/ksm/run" >> /etc/init.d/boot.local

    #NoHZ is not set

    #Disable AutoNUMA
    echo 0 > /proc/sys/kernel/numa_balancing
    echo "echo 0 > /proc/sys/kernel/numa_balancing" >> /etc/init.d/boot.local

    #Increase max open files
    echo 1048576 > /proc/sys/fs/nr_open
    echo "echo 1048576 > /proc/sys/fs/nr_open" >> /etc/init.d/boot.local

    zypper -n install gcc

    zypper -n install libgcc_s1 libstdc++6

    echo "#END: This section inserted by AWS SAP HANA Quickstart" >> /etc/init.d/boot.local
    echo "###################" >> /etc/init.d/boot.local
}

set_awsdataprovider() {
#install the AWS dataprovider require for AWS support

	cd /tmp
        aws s3 cp s3://aws-data-provider/bin/aws-agent_install.sh . > /dev/null

	if [ -f /tmp/aws-agent_install.sh ]
	then
		bash /tmp/aws-agent_install.sh > /dev/null
		echo 0
	else
		echo 1
	fi
}


set_ascsinifile() {
#set the vname of the ascs server in the INI file

     sed -i  "/NW_SCS_Instance.ascsVirtualHostname/ c\NW_SCS_Instance.ascsVirtualHostname = ${HOSTNAME}" $ASCS_INI_FILE
     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $ASCS_INI_FILE
     sed -i  "/hostAgent.sapAdmPassword/ c\hostAgent.sapAdmPassword = ${MP}" $ASCS_INI_FILE

     #set the SID
     sed -i  "/NW_GetSidNoProfiles.sid/ c\NW_GetSidNoProfiles.sid = ${SAP_SID}" $ASCS_INI_FILE

     #set the UID and GID
     sed -i  "/nwUsers.sidAdmUID/ c\nwUsers.sidAdmUID = ${SIDadmUID}" $ASCS_INI_FILE
     sed -i  "/nwUsers.sapsysGID/ c\nwUsers.sapsysGID = ${SAPsysGID}" $ASCS_INI_FILE

     #set the CD location based on $SW_TARGET
     sed -i  "/SAPINST.CD.PACKAGE.KERNEL/ c\SAPINST.CD.PACKAGE.KERNEL = ${SW_TARGET}/KERN_CD" $ASCS_INI_FILE
     sed -i  "/SAPINST.CD.PACKAGE.RDBMS/ c\SAPINST.CD.PACKAGE.RDBMS = ${SW_TARGET}/HDB_CLNTCD" $ASCS_INI_FILE

}


set_cleanup_ascsinifile() {
#clean up the INI file after finishing the SAP install

MP="DELETED"

	sed -i  "/hdb.create.dbacockpit.user/ c\hdb.create.dbacockpit.user = true" $INI_FILE

	#set the password from the SSM parameter store
	sed -i  "/NW_HDB_getDBInfo.systemPassword/ c\NW_HDB_getDBInfo.systemPassword = ${MP}" $INI_FILE
	sed -i  "/storageBasedCopy.hdb.systemPassword/ c\storageBasedCopy.hdb.systemPassword = ${MP}" $INI_FILE
	sed -i  "/HDB_Schema_Check_Dialogs.schemaPassword/ c\HDB_Schema_Check_Dialogs.schemaPassword = ${MP}" $INI_FILE
	sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $INI_FILE
     	sed -i  "/NW_HDB_getDBInfo.systemDbPassword/ c\NW_HDB_getDBInfo.systemDbPassword = ${MP}" $INI_FILE

	#set the profile directory
	sed -i  "/NW_readProfileDir.profileDir/ c\NW_readProfileDir.profileDir = /sapmnt/${SAP_SID}/profile" $INI_FILE

}

set_ntp() {
#set ntp in the /etc/ntp.conf file

	cp "$NTP_CONF_FILE" "$NTP_CONF_FILE.bak"
	echo "server 0.pool.ntp.org" >> "$NTP_CONF_FILE"
	echo "server 1.pool.ntp.org" >> "$NTP_CONF_FILE"
	echo "server 2.pool.ntp.org" >> "$NTP_CONF_FILE"
	echo "server 3.pool.ntp.org" >> "$NTP_CONF_FILE"

	systemctl start ntpd
	echo "systemctl start ntpd" >> /etc/init.d/boot.local

	_COUNT_NTP=$(grep ntp "$NTP_CONF_FILE" | wc -l)

	if [ "$_COUNT_NTP" -ge 4 ]
	then
		echo 0
	else
		echo 1
	fi
}

set_install_jq () {
#install jq s/w

	cd /tmp
	wget https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64
        mv jq-linux64 jq
        chmod 755 jq
}

set_filesystems() {
#create /usr/sap filesystem and mount /sapmnt


	    #bash /root/install/create-attach-single-volume.sh "50:gp2:$USR_SAP_DEVICE:$USR_SAP" > /dev/null
	    USR_SAP_VOLUME=$(lsblk  | grep $USR_SAP_VOL)

	    if [ -z "$USR_SAP_VOLUME" ]
	    then
		    echo "Exiting, can not create $USR_SAP_DEVICE or $SAPMNT_DEVICE EBS volumes"
	            #signal the waithandler, 1=Failed
	            /root/install/signalFinalStatus.sh 1 "Exiting, can not create $USR_SAP_DEVICE or $SAPMNT_DEVICE EBS volumes"
	            set_cleanup_ascsinifile
		    exit 1
	    else
		    mkdir $USR_SAP > /dev/null 2>&1
		    mkfs -t xfs $USR_SAP_DEVICE > /dev/null 2>&1
		    echo "$USR_SAP_DEVICE  $USR_SAP xfs nobarrier,noatime,nodiratime,logbsize=256k 0 0" >> $FSTAB_FILE 2>&1
		    mount -a > /dev/null 2>&1
		    mkswap $SWAP_DEVICE > /dev/null 2>&1
		    swapon $SWAP_DEVICE > /dev/null 2>&1
	    fi

}

set_dhcp() {

	sed -i '/DHCLIENT_SET_HOSTNAME/ c\DHCLIENT_SET_HOSTNAME="no"' $DHCP

	service network restart

	_DHCP=$(grep DHCLIENT_SET_HOSTNAME $DHCP | grep no)

	if [ -n "$_DHCP" ]
	then
		echo 0
	else
		echo 1
	fi
}

set_DB_hostname() {

	#add DB hostname
	echo "$DBIP  $DBHOSTNAME" >> $HOSTS_FILE

	#add own hostname
	MY_IP=$( ip a | grep inet | grep eth0 | awk -F"/" '{ print $1 }' | awk '{ print $2 }')
	echo "${MY_IP}"    "${HOSTNAME}" >> /etc/hosts  

	#echo "$SAP_PASIP  $SAP_PAS" >> $HOSTS_FILE
	#echo "$SAP_PASIP  $SAP_PAS" >> $HOSTS_FILE
	#echo "$SAP_ASCSIP  $SAP_ASCS" >> $HOSTS_FILE
}


set_net() {
#set and preserve the hostname


	#update DNS search order with our DNS Domain name
	sed -i "/NETCONFIG_DNS_STATIC_SEARCHLIST=""/ c\NETCONFIG_DNS_STATIC_SEARCHLIST="${HOSTED_ZONE}"" $NETCONFIG

	#update the /etc/resolv.conf file
	netconfig update -f > /dev/null

	sed -i '/preserve_hostname/ c\preserve_hostname: true' $CLOUD_CFG

	#disable dhcp
	_DISABLE_DHCP=$(set_dhcp)


	if [ "$HOSTNAME" == $(hostname) ]
	then
		echo 0
	else
		echo 1
	fi
}

set_services_file() {
#update the /etc/services file with customer supplied values

	cat "$SERVICES_FILE" >> $ETC_SVCS
}

set_nfsexport() {
#export the /sapmnt filesystem
     #need to check if /sapmnt filesystem files exists

     FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

     if [ "$FS_SAPMNT" ]
     then
	      echo "$SAPMNT      *(rw,no_root_squash,no_subtree_check)" >> /etc/exports
          chkconfig nfs on
          service nfsserver start
          echo "service nfsserver start" >> /etc/init.d/boot.local
          sleep 15
          exportfs -a
	      echo 0
     else
          #did not sucessfully export
          echo 1
     fi

}

set_sapmnt() {
#setup /sapmnt from the ASCS


	mkdir  $SAPMNT
    
    #look for the SAPMNT volume
    SAPMNT_VOLUME=$(lsblk | grep $SAPMNT_VOL ) > /dev/null


    #Check if EFS is in use, if EFS is in use then we mount up from the EFS share
	if [ "$EFS" == "Yes" ]
	then
		#mount up EFS
        echo "Mounting up EFS from this EFS location: "
        
        #construct the EFS DNS name
        EFS_MP=""$EFS_MT".efs."$REGION".amazonaws.com:/ "

        echo ""$EFS_MP"  "$SAPMNT"  nfs rw,soft,bg,timeo=3,intr 0 0"  >> $FSTAB_FILE
        
        #try to mount /sapmnt 3 times 
        mount /sapmnt > /dev/null
        sleep 5

       #validate /sapmnt filesystems were created and mounted
        FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

        if [ -z "$FS_SAPMNT" ]
        then

            mount /sapmnt > /dev/null
            sleep 15
        fi

       #validate /sapmnt filesystems were created and mounted
        FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

        if [ -z "$FS_SAPMNT" ]
        then

            mount /sapmnt  > /dev/null
            sleep 60
        fi
    else
        #EFS is no, so we create a local /sapmnt filesystem and share it out
        if [ -z "$SAPMNT_VOLUME" ]
        then
            echo "Exiting, can not create $SAPMNT_DEVICE EBS volues" 
            #signal the waithandler, 1=Failed
            /root/install/signalFinalStatus.sh 1 "Exiting, can not create $SAPMNT_DEVICE EBS volues"
            set_cleanup_inifiles
            exit 1
        else
            mkdir $SAPMNT > /dev/null
            mkdir $SW > /dev/null
        fi

         mkfs -t xfs $SAPMNT_DEVICE > /dev/null

         #create /etc/fstab entries
         echo "$SAPMNT_DEVICE   $SAPMNT  xfs nobarrier,noatime,nodiratime,logbsize=256k 0 0" >> $FSTAB_FILE

        #try to mount /sapmnt 3 times 
        mount /sapmnt > /dev/null
        sleep 5

        #validate /sapmnt filesystems were created and mounted
        FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

        if [ -z "$FS_SAPMNT" ]
        then

            mount /sapmnt > /dev/null
            sleep 15
        fi

       #validate /sapmnt filesystems were created and mounted
        FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

        if [ -z "$FS_SAPMNT" ]
        then

            mount /sapmnt > /dev/null
            sleep 60
        fi

         #validate /usr/sap and /sapmnt filesystems were created and mounted
         FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

        if [ -z "$FS_SAPMNT" ]
        then
	        #we did not successfully created the filesystems and mount points	
	        echo 1
        else
	        #we did successfully created the filesystems and mount points
            #we now share it out, call teh set_nfsexport function

            set_nfsexport
        
            echo
            echo "Start set_nfsexport @ $(date) from withing set_sapmnt function"
            echo
            _SET_NFS=$(set_nfsexport)

            if [ "$_SET_NFS" == 0 ]
            then
                 echo "Successfully set and exported /sapmnt"
            else
                 echo "FAILED to set /sapmnt"
                 /root/install/signalFinalStatus.sh 1 "FAILED to set /sapmnt filesyste"
                 exit
            fi
	        echo 0
        fi
  fi
}

set_uuidd() {
#Install the uuidd daemon per SAP Note 1391070

	zypper -n install uuidd > /dev/null 2>&1
	chkconfig uuidd on > /dev/null 2>&1
	service uuidd start > /dev/null 2>&1

        _UUIDD_RUNNING=$(ps -ef | grep uuidd | grep -v grep)

	if [ -n "$_UUIDD_RUNNING" ]
	then
		echo 0
	else
		echo 1
	fi
}

set_update_cli() {
#update the aws cli
	zypper -n install python-pip > /dev/null 2>&1

	pip install --upgrade --user awscli > /dev/null 2>&1

	_AWS_CLI=$(aws --version 2>&1)

	if [ -n "$_AWS_CLI" ]
	then
		echo 0
	else
		echo 1
	fi
}


set_install_ssm() {

	cd /tmp

	wget https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm > /dev/null 2>&1

	rpm -ivh /tmp/amazon-ssm-agent.rpm > /dev/null 2>&1

	echo '#!/usr/bin/sh' > /etc/init.d/ssm
	echo "service amazon-ssm-agent start" >> /etc/init.d/ssm

	chmod 755 /etc/init.d/ssm

	chkconfig ssm on > /dev/null 2>&1

	_SSM_RUNNING=$(ps -ef | grep ssm | grep -v grep)

	if [ -n "$_SSM_RUNNING" ]
	then
		echo 0
	else
		echo 1
	fi
}



set_s3_download() {
#download the s/w
          

          #download the media from the S3 bucket provided
          _S3_DL=$(aws s3 sync "s3://${S3_BUCKET}/${S3_BUCKET_KP}" "$SW_TARGET" 2>&1 >/dev/null | grep "download failed")

          if [ -n "$S3_DL" ]
          then
               #download failed for some reason, try to download again
               _S3_DL2=$(aws s3 sync "s3://${S3_BUCKET}/${S3_BUCKET_KP}" "$SW_TARGET" 2>&1 >/dev/null | grep "download failed")
        
              if [ -n "$S3_DL2" ]
              then
                   #download failed on 2nd try, exit
                   echo 1
                   return
              fi
              
          fi

	      cd "$SRC_INI_DIR" 
          cp *.params  "$SW_TARGET"

          if [ -d "$SAPINST" ]
          then
              chmod -R 755 $SW_TARGET > /dev/null 
	          cd "$SRC_INI_DIR" 
              cp *.params  "$SW_TARGET"
              echo 0
          else
	      #retry the download again
              aws s3 sync "s3://${S3_BUCKET}/${S3_BUCKET_KP}" "$SW_TARGET" > /dev/null
              #aws s3 sync "$S3_BUCKET/$S3_BUCKET_KP" "$SW_TARGET" > /dev/null


 	      if [ -d "$SAPINST" ]
	      then
              	   chmod -R 755 $SW_TARGET > /dev/null 
	          cd "$SRC_INI_DIR" 
              cp *.params  "$SW_TARGET"
                   echo 0
              else
                   echo 1

              fi
          fi
}

set_save_services_file() {
#save the /etc/services file from the ASCS instance for other instances

     grep -i sap "$ETC_SVCS" > "$SAPMNT_SVCS"

     #need to check if services files exists
     if [ -s "$SAPMNT_SVCS" ]
     then
          echo 0
     else
          echo 1
     fi

}

set_SUSE_BYOS() {

#Check to see if BYOS SLES registration is successful

    if [[ "$MyOS" =~ BYOS ]];
    then
        SUSEConnect -r "$SLESBYOSRegCode" > /dev/null
        sleep 5
        CheckSLESRegistration=$(SUSEConnect -s | grep ACTIVE)
        if [ -n "$CheckSLESRegistration" ]
        then
          SUSEConnect -p sle-module-public-cloud/12/x86_64 > /dev/null
          echo 0
        else
          echo 1
        fi
    fi
}

###Main Body###

if [ -f "/etc/sap-app-quickstart" ]
then
        echo "****************************************************************"
	echo "****************************************************************"
        echo "The /etc/sap-app-quickstart file exists, exiting the Quick Start"
        echo "****************************************************************"
        echo "****************************************************************"
        exit 0
fi

#Check to see if this is a BYOS system and register it if it is
if [[ "$MyOS" =~ BYOS ]];
then
    _SUSE_BYOS=$(set_SUSE_BYOS)

    if [ "$_SUSE_BYOS" == 0 ]
    then
	    echo "Successfully setup BYOS"
    else
	    echo "FAILED to setup BYOS...exiting"
	    #signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to setup BYOS...exiting"
	    set_cleanup_aasinifile
	    exit 1
    fi
fi

_SET_NET=$(set_net)


if [ "$HOSTNAME" == $(hostname) ]
then
	echo "Successfully set and updated hostname"
	set_DB_hostname
else
	echo "FAILED to set hostname"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Failed to set hostname"
	set_cleanup_ascsinifile
	exit 1
fi

_SET_AWSCLI=$(set_update_cli)

if [ "$_SET_AWSCLI" == 0 ]
then
	echo "Successfully installed AWS CLI"
else
	echo "FAILED to install AWS CLI...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to install AWS CLI...exiting"
	set_cleanup_ascsinifile
	exit 1
fi

set_oss_configs


_SET_SSM=$(set_install_ssm)

if [ "$_SET_SSM" == 0 ]
then
	echo "Successfully installed SSM"
else
	echo "FAILED to install SSM...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to install ssm...exiting"
	set_cleanup_ascsinifile
	exit 1
fi


_SET_UUIDD=$(set_uuidd)

if [ "$_SET_UUIDD" == 0 ]
then
	echo "Successfully installed UUIDD"
else
	echo "FAILED to install UUIDD...exiting"
fi


_SET_TZ=$(set_tz)

if [ "$_SET_TZ" == 0 ]
then
	echo "Successfully updated TimeZone"
else
	echo "FAILED to update TimeZone...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to update TimeZone...exiting"
	set_cleanup_ascsinifile
	exit 1
fi

_SET_NTP=$(set_ntp)

if [ "$_SET_NTP" == 0 ]
then
	echo "Successfully updated NTP"
else
	echo "FAILED to update NTP...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to update NTP...exiting"
	set_cleanup_ascsinifile
	exit 1
fi

set_install_jq

_SET_AWSDP=$(set_awsdataprovider)

if [ "$_SET_AWSDP" == 0 ]
then
	echo "Successfully installed AWS Data Provider"
else
	echo "FAILED to install AWS Data Provider...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Failed to install AWS Data Provider...exiting"
	set_cleanup_ascsinifile
	exit 1
fi


_SET_FILESYSTEMS=$(set_filesystems)

_VAL_USR_SAP=$(df -h $USR_SAP) 

if [ -n "$_VAL_USR_SAP" ]
then
	echo "Successfully updated $USR_SAP filesystem"
else
	echo "FAILED to update $USR_SAP filesystem...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "FAILED to  update $USR_SAP filesystem...exiting"
	set_cleanup_ascsinifile
	exit 1
fi


_SET_SAPMNT=$(set_sapmnt)

_SAPMNT=$(df -h $SAPMNT | awk '{ print $NF }' | tail -1)


if [ "$_SAPMNT" == "$SAPMNT"  ]
then
	echo "Successfully setup /sapmnt"
else
	echo "Failed to mount $SAPMNT...exiting"
	#signal the waithandler, 1=Failed
       	/root/install/signalFinalStatus.sh 1 "Failed to mount $SAPMNT, tried $COUNT times...exiting"
	set_cleanup_ascsinifile
	exit 1
fi


#recreate the SSM param store as encrypted
_MPINV=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $1}' | grep INVALID | wc -l)

_MPVAL=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $NF}' | wc -l)

#_MPINV will be 1 when aws ssm get-parameters returns the INVALID response

while [ "$_MPVAL" -eq 0 -a "$_MPINV" -eq 1 ]
do
	echo "Waiting for SSM parameter store: $SSM_PARAM_STORE @ $(date)..."
    #_MPINV will be 0 when aws ssm get-parameters command returns a valid response
	_MPINV=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $1}' | grep INVALID | wc -l)
	sleep 15
done


MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $4}')
INVALID_MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $1}')

if [ "$INVALID_MP" == "INVALIDPARAMETERS" ]
then
	echo "Invalid encrypted SSM Parameter store: $SSM_PARAM_STORE...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Invalid SSM Parameter Store...exiting"
	set_cleanup_ascsinifile
	exit 1
fi

if [ -z "$MP" ]
then
	echo "Could not read encrypted SSM Parameter store: $SSM_PARAM_STORE...exiting"
	#signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Could not read encrypted SSM Parameter store: $SSM_PARAM_STORE...exiting"
	set_cleanup_ascsinifile
	exit 1
fi

#Download the s/w
echo
echo "Start set_s3_download @ $(date)"
echo
_SET_S3=$(set_s3_download)


if [ "$_SET_S3" == 0 ]
then
     echo "Successfully downloaded the s/w"
else
     echo
     echo "FAILED to download s/w to /sapmnt..."
     echo "check /sapmnt/SWPM and permissions to your S3 SAP software bucket and key prefix:"$S3_BUCKET"/"$S3_BUCKET_KP" "
     #log the error message
     aws s3 sync "s3://${S3_BUCKET}/${S3_BUCKET_KP}" "$SW_TARGET" > /tmp/nw_s3_downnload_error.log 2>&1
     S3_ERR=$(cat /tmp/nw_s3_downnload_error.log)
     #signal the waithandler, 1=Failed
     /root/install/signalFinalStatus.sh 1 \""FAILED to set /usr/sap and /sapmnt...check /sapmnt/SWPM and permissions to your S3 SAP software bucket:"$S3_BUCKET"/"$S3_BUCKET_KP" ERR= \"$S3_ERR\" "\"
     set_cleanup_inifiles
     exit
fi


if [ "$INSTALL_SAP" == "No" ]
then
	echo "Completed setting up SAP App Server Infrastrucure."
	echo "Exiting as the option to install SAP software was set to: $INSTALL_SAP"
	#signal the waithandler, 0=Success
	/root/install/signalFinalStatus.sh 0 "Finished. Exiting as the option to install SAP software was set to: $INSTALL_SAP"
	exit 0

fi


###Execute sapinst###


set_ascsinifile

cd $SAPINST
sleep 1
./sapinst SAPINST_INPUT_PARAMETERS_URL="$ASCS_INI_FILE" SAPINST_EXECUTE_PRODUCT_ID="$PRODUCT" SAPINST_USE_HOSTNAME="$HOSTNAME" SAPINST_SKIP_DIALOGS="true"

SID=$(echo "$SAP_SID" |tr '[:upper:]' '[:lower:]')
SIDADM=$(echo $SID\adm)

su - "$SIDADM" -c "stopsap $HOSTNAME"
sleep 5
su - "$SIDADM" -c "startsap $HOSTNAME"

sleep 15

#test if SAP is up
_SAP_UP=$(netstat -an | grep 32"$SAPInstanceNum" | grep tcp | grep LISTEN | wc -l )

echo "This is the value of SAP_UP: $_SAP_UP"

if [ "$_SAP_UP" -eq 1 ]
then
	echo "Successfully installed SAP"
	set_cleanup_ascsinifile

	
    #create the /etc/sap-app-quickstart file
    #Save the sap entries in /etc/services to the /sapmnt share for PAS and ASCS instances

    _SET_SERVICES=$(set_save_services_file)

    if [ "$_SET_SERVICES" == 0 ]
    then
         echo "Successfully set services file"
    else
         echo  "FAILED to set services file"
     set_cleanup_inifiles
     /root/install/signalFinalStatus.sh 1 "FAILED to set services file"
     exit 1
    fi

	touch /etc/sap-app-quickstart
    #signal the waithandler, 0=Success
    /root/install/signalFinalStatus.sh 0 "Successfully installed SAP. SAP_UP value is: $_SAP_UP"
    exit 0
else
	#retry the ASCS install
    chown -R "$SIDADM" /sapmnt/$SAP_SID
        cd $SAPINST
    sleep 1
    ./sapinst SAPINST_INPUT_PARAMETERS_URL="$ASCS_INI_FILE" SAPINST_EXECUTE_PRODUCT_ID="$PRODUCT" SAPINST_USE_HOSTNAME="$HOSTNAME" SAPINST_SKIP_DIALOGS="true"

    sleep 5

    #test if SAP is up
    _SAP_UP2=$(netstat -an | grep 32"$SAPInstanceNum" | grep tcp | grep LISTEN | wc -l )

    echo "This is the value of SAP_UP2: $_SAP_UP2"

    if [ "$_SAP_UP2" -eq 1 ]
    then
    	echo "Successfully installed SAP"
	    set_cleanup_ascsinifile

	
        #create the /etc/sap-app-quickstart file
        #Save the sap entries in /etc/services to the /sapmnt share for PAS and ASCS instances

        _SET_SERVICES=$(set_save_services_file)

        if [ "$_SET_SERVICES" == 0 ]
        then
                echo "Successfully set services file"
        else
                echo  "FAILED to set services file"
                set_cleanup_inifiles
                /root/install/signalFinalStatus.sh 1 "FAILED to set services file"
                exit 1
        fi

	    touch /etc/sap-app-quickstart
        #signal the waithandler, 0=Success
        /root/install/signalFinalStatus.sh 0 "Successfully installed SAP. SAP_UP value is: $_SAP_UP"
        exit 0
    else
        echo "SAP installed FAILED."
	    set_cleanup_ascsinifile
	    #signal the waithandler, 0=Success
	    _ERR_LOG=$(find /tmp -type f -name "sapinst_dev.log")
	    _PASS_ERR=$(grep ERR "$_ERR_LOG" | grep -i password)
	    /root/install/signalFinalStatus.sh 1 "SAP ASCS install RETRY Failed...ASCS not installed 2nd retry...password error?= "$_PASS_ERR" "
   fi
fi
