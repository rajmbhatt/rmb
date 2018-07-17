#!/bin/bash -xv
#Version 1.3
# Last Modified : 07/17/2018 08:36:00 AM EST



#
#   This code was written by rmb@amazon.com.
#   This sample code is provided on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#



###Global Variables###
source /root/install/config.sh
TZ_LOCAL_FILE="/etc/localtime"
NTP_CONF_FILE="/etc/ntp.conf"
USR_SAP="/usr/sap"
SAPMNT="/sapmnt"
SYB="/sybase"
SYBSIDFS="/sybase/${SID}"
SYBSIDDATA1="/sybase/${SID}/sapdata_1"
SYBSIDDATA2="/sybase/${SID}/sapdata_2"
SYBSIDDATA3="/sybase/${SID}/sapdata_3"
SYBSIDDATA4="/sybase/${SID}/sapdata_4"
SYBSIDLOG1="/sybase/${SID}/saplog_1"

FSTAB_FILE="/etc/fstab"
DHCP="/etc/sysconfig/network/dhcp"
CLOUD_CFG="/etc/cloud/cloud.cfg"
NETCONFIG="/etc/sysconfig/network/config"
IP=$(curl http://169.254.169.254/latest/meta-data/local-ipv4/)
HOSTS_FILE="/etc/hosts"
HOSTNAME_FILE="/etc/HOSTNAME"
ETC_SVCS="/etc/services"
SAPMNT_SVCS="/sapmnt/SWPM/services"

ASCS_DONE="/sapmnt/SWPM/ASCS_DONE"
PAS_DONE="/sapmnt/SWPM/PAS_DONE"
MASTER_HOSTS="/sapmnt/SWPM/master_etc_hosts"
REGION=$(curl http://169.254.169.254/latest/dynamic/instance-identity/document/ | grep -i region | awk '{ print $3 }' | sed 's/"//g' | sed 's/,//g')
#
###  Variables below need to be CUSTOMIZED for your environment  ###
#
HOSTNAME=$(hostname)

###Functions###

#Set variables based on which SAP NW version we are installing


    ASCS_INI_FILE="/sapmnt/NW75/SWPM/ASCS_00_Linux_HDB.params"
    PAS_INI_FILE="/sapmnt/NW75/SWPM/PASX_D00_Linux_HDB.params"
    DB_INI_FILE="/sapmnt/NW75/SWPM/DB_00_Linux_HDB.params"
    ASCS_PRODUCT="NW_ABAP_ASCS:NW750.HDB.ABAPHA"
    PAS_Standalone_ASE_INI_FILE="/sapmnt/NW75/scripts/Standalone_D00_Linux_ASE.params"
    DB_PRODUCT="NW_ABAP_DB:NW750.HDB.ABAPHA"
    PAS_PRODUCT="NW_ABAP_CI:NW750.HDB.ABAPHA"
    SW_TARGET="/sapmnt/NW75"
    SRC_INI_DIR="/root/install"
    SAPINST="/sapmnt/NW75/SWPM/"


set_install_jq () {
#install jq s/w

	cd /tmp
	wget https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64
        mv jq-linux64 jq
        chmod 755 jq
}

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

set_install_ssm() {

	cd /tmp
	curl  "https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm" -o amazon-ssm-agent.rpm

	rpm -ivh /tmp/amazon-ssm-agent.rpm

	echo '#!/usr/bin/sh' > /etc/init.d/ssm
	echo "service amazon-ssm-agent start" >> /etc/init.d/ssm

	chmod 755 /etc/init.d/ssm

	chkconfig ssm on

}

set_dbinifile() {
#set the vname of the database server in the INI file

     #set the db server hostname
     sed -i  "/NW_HDB_getDBInfo.dbhost/ c\NW_HDB_getDBInfo.dbhost = ${DBHOSTNAME}" $DB_INI_FILE
     sed -i  "/hdb.create.dbacockpit.user/ c\hdb.create.dbacockpit.user = false" $DB_INI_FILE

     #set the password from the SSM parameter store
     sed -i  "/NW_HDB_getDBInfo.systemPassword/ c\NW_HDB_getDBInfo.systemPassword = ${MP}" $DB_INI_FILE
     sed -i  "/storageBasedCopy.hdb.systemPassword/ c\storageBasedCopy.hdb.systemPassword = ${MP}" $DB_INI_FILE
     sed -i  "/HDB_Schema_Check_Dialogs.schemaPassword/ c\HDB_Schema_Check_Dialogs.schemaPassword = ${MP}" $DB_INI_FILE
     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $DB_INI_FILE
     sed -i  "/NW_HDB_DB.abapSchemaPassword/ c\NW_HDB_DB.abapSchemaPassword = ${MP}" $DB_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemDbPassword/ c\NW_HDB_getDBInfo.systemDbPassword = ${MP}" $DB_INI_FILE

     #set the SID and Schema
     sed -i  "/NW_HDB_getDBInfo.dbsid/ c\NW_HDB_getDBInfo.dbsid = ${SAP_SID}" $DB_INI_FILE
     sed -i  "/NW_readProfileDir.profileDir/ c\NW_readProfileDir.profileDir = /sapmnt/${SAP_SID}/profile" $DB_INI_FILE
     sed -i  "/HDB_Schema_Check_Dialogs.schemaName/ c\HDB_Schema_Check_Dialogs.schemaName = ${SAP_SCHEMA_NAME}" $DB_INI_FILE
     sed -i  "/NW_HDB_DB.abapSchemaName/ c\NW_HDB_DB.abapSchemaName = ${SAP_SCHEMA_NAME}" $DB_INI_FILE

     #set the UID and GID
     sed -i  "/nwUsers.sidAdmUID/ c\nwUsers.sidAdmUID = ${SIDadmUID}" $DB_INI_FILE
     sed -i  "/nwUsers.sapsysGID/ c\nwUsers.sapsysGID = ${SAPsysGID}" $DB_INI_FILE

     #set the CD location based on $SW_TARGET
     sed -i  "/SAPINST.CD.PACKAGE.KERNEL/ c\SAPINST.CD.PACKAGE.KERNEL = ${SW_TARGET}/KERN_CD" $DB_INI_FILE
     sed -i  "/SAPINST.CD.PACKAGE.RDBMS/ c\SAPINST.CD.PACKAGE.RDBMS = ${SW_TARGET}/HDB_CLNTCD" $DB_INI_FILE
     sed -i  "/SAPINST.CD.PACKAGE.LOAD/ c\SAPINST.CD.PACKAGE.LOAD = ${SW_TARGET}/EXP_CD" $DB_INI_FILE

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


set_netweaverstandaloneaseinifile() {
#set the vname of the database server in the INI file

    sed -i "/NW_ABAP_Import_Dialog.dbCodepage/ c\NW_ABAP_Import_Dialog.dbCodepage = 4103" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_ABAP_Import_Dialog.migmonJobNum/ c\NW_ABAP_Import_Dialog.migmonJobNum= 29" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_ABAP_Import_Dialog.migmonLoadArgs/ c\NW_ABAP_Import_Dialog.migmonLoadArgs = -c 100000 -loadprocedure fast" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance.ascsInstanceNumber/ c\NW_CI_Instance.ascsInstanceNumber = 02" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance.ascsVirtualHostname/ c\NW_CI_Instance.ascsVirtualHostname = ${SAPPAS_HOSTNAME}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance.ciInstanceNumber/ c\NW_CI_Instance.ciInstanceNumber = ${SAPInstanceNum}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance.ciVirtualHostname/ c\NW_CI_Instance.ciVirtualHostname = ${SAPPAS_HOSTNAME}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance.scsVirtualHostname/ c\NW_CI_Instance.scsVirtualHostname = ${SAPPAS_HOSTNAME}"  $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_CI_Instance_ABAP_Reports.executeReportsForDepooling/ c\NW_CI_Instance_ABAP_Reports.executeReportsForDepooling = true" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_Delete_Sapinst_Users.removeUsers/ c\NW_Delete_Sapinst_Users.removeUsers = true" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_GetMasterPassword.masterPwd/  c\NW_GetMasterPassword.masterPwd = ${MP}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_GetSidNoProfiles.sid/ c\NW_GetSidNoProfiles.sid = ${SAP_SID}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_SYB_DBPostload.numberParallelStatisticJobs/ c\NW_SYB_DBPostload.numberParallelStatisticJobs = 0" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_System.installSAPHostAgent/ c\NW_System.installSAPHostAgent = false" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_getFQDN.FQDN/ c\NW_getFQDN.FQDN = net.bms.com" $PAS_Standalone_ASE_INI_FILE
	sed -i "/NW_getLoadType.loadType/ c\NW_getLoadType.loadType = SAP" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.aseSortOrder/ c\SYB.NW_DB.aseSortOrder = binaryalt" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.databaseDevices/ c\SYB.NW_DB.databaseDevices = data DISK for SAP,/sybase/${SID}/sapdata_1,150,,,${SID}_data_001,data DISK for SAP,/sybase/${SID}/sapdata_2,150,,,${SID}_data_002,data DISK for SAP,/sybase/${SID}/sapdata_3,150,,,${SID}_data_003,data DISK for SAP,/sybase/${SID}/sapdata_4,150,,,${SID}_data_004,log DISK for SAP,/sybase/${SID}/saplog_1,50,,,${SID}_log_001,data DISK for saptools,/sybase/${SID}/sapdiag,2,,,saptools_data_001,log DISK for saptools,/sybase/${SID}/sapdiag,2,,,saptools_log_001,data DISK for sybsecurity,/sybase/${SID}/sybsecurity,0.2,,,sybsecurity_data_001,log DISK for sybsecurity,/sybase/${SID}/sybsecurity,0.02,,,sybsecurity_log_001,temp DISK for SAP,/sybase/${SID}/sybtemp,5,,,sybtempdb_data_001,"  $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.encryptionMasterKeyPassword/ c\SYB.NW_DB.encryptionMasterKeyPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.folderSystemDISKs/ c\SYB.NW_DB.folderSystemDISKs = /sybase/${SID}/sybsystem" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.folderTempdbDISK/ c\SYB.NW_DB.folderTempdbDISK= /sybase/${SID}/sybtemp" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.portBackupServer/ c\SYB.NW_DB.portBackupServer= 4902" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.portDatabaseServer/ c\SYB.NW_DB.portDatabaseServer = 4901" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.portJobScheduler/ c\SYB.NW_DB.portJobScheduler = 4903" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.portXPServer/ c\SYB.NW_DB.portXPServer = 4904" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.sqlServerConnections/ c\SYB.NW_DB.sqlServerConnections = 200" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.sqlServerCores/ c\SYB.NW_DB.sqlServerCores = 16" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.sqlServerHostname/ c\SYB.NW_DB.sqlServerHostname = ${SAPPAS_HOSTNAME}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.sqlServerMemory/ c\SYB.NW_DB.sqlServerMemory = 7000" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SYB.NW_DB.sslPassword/ c\SYB.NW_DB.sslPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/archives.downloadBasket/ c\archives.downloadBasket = ${SW_TARGET}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/nwUsers.sapsysGID/ c\nwUsers.sapsysGID = ${SAPSYSUID}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/nwUsers.sidAdmUID/ c\nwUsers.sidAdmUID = ${SIDadmUID}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/nwUsers.sidadmPassword/ c\nwUsers.sidadmPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/nwUsers.syb.sybsidPassword/ c\nwUsers.syb.sybsidPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SAPINST.CD.PACKAGE.KERNEL/ c\SAPINST.CD.PACKAGE.KERNEL = ${SW_TARGET}/KERNEL" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SAPINST.CD.PACKAGE.RDBMS/ c\SAPINST.CD.PACKAGE.RDBMS = ${SW_TARGET}/BD_SYBASE_ASE_16.0.03.04_RDBMS_for_BS_" $PAS_Standalone_ASE_INI_FILE
	sed -i "/SAPINST.CD.PACKAGE.LOAD/ c\SAPINST.CD.PACKAGE.LOAD = ${SW_TARGET}/EXPORTS" $PAS_Standalone_ASE_INI_FILE
}

set_pasinifile() {
#set the vname of the database server in the INI file

     sed -i  "/hdb.create.dbacockpit.user/ c\hdb.create.dbacockpit.user = true" $PAS_INI_FILE

     #set the password from the SSM parameter store
     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $PAS_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemPassword/ c\NW_HDB_getDBInfo.systemPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/storageBasedCopy.hdb.systemPassword/ c\storageBasedCopy.hdb.systemPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/storageBasedCopy.abapSchemaPassword/ c\storageBasedCopy.abapSchemaPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/HDB_Schema_Check_Dialogs.schemaPassword/ c\HDB_Schema_Check_Dialogs.schemaPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemDbPassword/ c\NW_HDB_getDBInfo.systemDbPassword = ${MP}" $PAS_INI_FILE

     #set the profile directory
     sed -i  "/NW_readProfileDir.profileDir/ c\NW_readProfileDir.profileDir = /sapmnt/${SAP_SID}/profile" $PAS_INI_FILE
     
     #set the SID and Schema
     sed -i  "/HDB_Schema_Check_Dialogs.schemaName/ c\HDB_Schema_Check_Dialogs.schemaName = ${SAP_SCHEMA_NAME}" $PAS_INI_FILE

     #set the UID and GID
     sed -i  "/nwUsers.sidAdmUID/ c\nwUsers.sidAdmUID = ${SIDadmUID}" $PAS_INI_FILE
     sed -i  "/nwUsers.sapsysGID/ c\nwUsers.sapsysGID = ${SAPsysGID}" $PAS_INI_FILE

     
     #set the CD location based on $SW_TARGET
     sed -i  "/SAPINST.CD.PACKAGE.KERNEL/ c\SAPINST.CD.PACKAGE.KERNEL = ${SW_TARGET}/KERN_CD" $PAS_INI_FILE
     sed -i  "/SAPINST.CD.PACKAGE.RDBMS/ c\SAPINST.CD.PACKAGE.RDBMS = ${SW_TARGET}/HDB_CLNTCD" $PAS_INI_FILE
     sed -i  "/SAPINST.CD.PACKAGE.LOAD/ c\SAPINST.CD.PACKAGE.LOAD = ${SW_TARGET}/EXP_CD" $PAS_INI_FILE

}

set_cleanup_inifiles() {
#cleanup the password in the  the INI files

     MP="DELETED"
     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $ASCS_INI_FILE
     sed -i  "/hostAgent.sapAdmPassword/ c\hostAgent.sapAdmPassword = ${MP}" $ASCS_INI_FILE

     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $PAS_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemPassword/ c\NW_HDB_getDBInfo.systemPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/storageBasedCopy.hdb.systemPassword/ c\storageBasedCopy.hdb.systemPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/storageBasedCopy.abapSchemaPassword/ c\storageBasedCopy.abapSchemaPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/HDB_Schema_Check_Dialogs.schemaPassword/ c\HDB_Schema_Check_Dialogs.schemaPassword = ${MP}" $PAS_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemPassword/ c\NW_HDB_getDBInfo.systemPassword = ${MP}" $DB_INI_FILE
     sed -i  "/storageBasedCopy.hdb.systemPassword/ c\storageBasedCopy.hdb.systemPassword = ${MP}" $DB_INI_FILE
     sed -i  "/HDB_Schema_Check_Dialogs.schemaPassword/ c\HDB_Schema_Check_Dialogs.schemaPassword = ${MP}" $DB_INI_FILE
     sed -i  "/NW_GetMasterPassword.masterPwd/ c\NW_GetMasterPassword.masterPwd = ${MP}" $DB_INI_FILE
     sed -i  "/NW_HDB_DB.abapSchemaPassword/ c\NW_HDB_DB.abapSchemaPassword = ${MP}" $DB_INI_FILE
     sed -i  "/NW_HDB_getDBInfo.systemDbPassword/ c\NW_HDB_getDBInfo.systemDbPassword = ${MP}" $PAS_INI_FILE
	
	 sed -i "/NW_GetMasterPassword.masterPwd  c\NW_GetMasterPassword.masterPwd = ${MP}" $PAS_Standalone_ASE_INI_FILE
	 sed -i "/SYB.NW_DB.encryptionMasterKeyPassword c\SYB.NW_DB.encryptionMasterKeyPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	 sed -i "/SYB.NW_DB.sslPassword c\SYB.NW_DB.sslPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	 sed -i "/nwUsers.sidadmPassword c\nwUsers.sidadmPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
	 sed -i "/nwUsers.syb.sybsidPassword c\nwUsers.syb.sybsidPassword = ${MP}" $PAS_Standalone_ASE_INI_FILE
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

set_oss_configs() {

    #This section is from OSS #2205917 - SAP HANA DB: Recommended OS settings for SLES 12 / SLES for SAP Applications 12
    #and OSS #2292711 - SAP HANA DB: Recommended OS settings for SLES 12 SP1 / SLES for SAP Applications 12 SP1 

   
    echo "###################" >> /etc/init.d/boot.local
    echo "#BEGIN: This section inserted by AWS SAP Quickstart" >> /etc/init.d/boot.local

    #Disable THP
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo "echo never > /sys/kernel/mm/transparent_hugepage/enabled" >> /etc/init.d/boot.local

    echo 10 > /proc/sys/vm/swappiness
    echo "echo 10 > /proc/sys/vm/swappiness" >> /etc/init.d/boot.local

	# Install OS Packages for supporting SAP Application Workloads
	
	# Setup Repo
	yum install -y createrepo --disablerepo=saprepo
	createrepo -g SAPGroup.xml /srv/sap/repo
	yum clean all
	
	# Install SAP Packages (Workaround until the RHEL Subscription issue is resolved)
	yum groupinstall 'SAP Group' -y

    echo "#END: This section inserted by AWS SAP HANA Quickstart" >> /etc/init.d/boot.local
    echo "###################" >> /etc/init.d/boot.local
	
	echo "Set selinux parameters"
	sed -i "/SELINUX=enforcing/ c\SELINUX=permissive" /etc/selinux/config
	setenforce 0
}


set_ntp() {
#set ntp in the /etc/ntp.conf file

     systemctl start ntpd
	 systemctl enable ntpd
     
     COUNT_NTP=$(grep ntp "$NTP_CONF_FILE" | wc -l)

     if [ "$COUNT_NTP" -ge 4 ]
     then
          echo 0
     else
          #did not sucessfully update ntp config
          echo 1
     fi
}

set_filesystems() {
#create /usr/sap filesystem and mount /sapmnt

    USR_SAP_VOLUME=$(lsblk | grep ${USR_SAP_DISK}) > /dev/null
    SAPMNT_VOLUME=$(lsblk | grep ${SAPMNT_DISK}) > /dev/null
	SUM_VOLUME=$(lsblk | grep ${SUM_DISK}) > /dev/null
		

    if [ -z "$USR_SAP_VOLUME" -o -z "$SAPMNT_VOLUME" -o -z "$SUM_VOLUME" ]
    then
        echo "Exiting, can not create $USR_SAP_DISK or $SAPMNT_DISK or $SUM_VOLUME EBS volumes" 
        #signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Exiting, can not create $USR_SAP_DISK or $SAPMNT_DISK EBS or $SUM_VOLUME volumes"
        set_cleanup_inifiles
        exit 1
    else
        mkdir $USR_SAP > /dev/null
        mkdir $SAPMNT > /dev/null
        #mkdir $SW > /dev/null
    fi

	# Create VGs and LVs for SAP Software Directories
		pvcreate /dev/${USR_SAP_VOLUME} /dev/${SAPMNT_VOLUME} /dev/${SUM_VOLUME}
		vgcreate vgsapbin /dev/$USR_SAP_DISK
		vgcreate vgsapmnt /dev/$SAPMNT_DISK
		vgcreate vgsapsum /dev/$SUM_DISK
		lvcreate -n lvsapbin -L 25G vgsapbin
		lvcreate -n lvsaphostctrl -L 5G vgsapbin
		lvcreate -n lvsapdaa -L 5G vgsapbin
		lvcreate -n lvsaptrans -L 10G vgsapbin
		lvcreate -n lvbms -L 1G vgsapbin
		
		## SAPMNT LV creation
		lvcreate -n lvsapmnt -L 50G vgsapmnt
		
		## Allocating 90% of space allocated to SUM Drive
		SUMSIZE="$(( ${SUMVolSize}*95/100 ))"
		lvcreate -n lvsapsum -L ${SUMSIZE}G vgsapsum
		
		# Loop Through filesystem creation
		for i in lvsapbin lvsaphostctrl lvsapdaa lvsaptrans lvbms
		do
			mkfs.xfs /dev/mapper/vgsapbin-${i}
		done
		
		## Create XFS filesystems for remaining LVs
		mkfs.xfs /dev/mapper/vgsapsum-lvsapsum
		mkfs.xfs /dev/mapper/vgsapmnt-lvsapmnt
		
		# Mount SAP Filesystems in correct order and create Directories
		
		mount /dev/mapper/vgsapbin-lvsapbin ${USR_SAP}
		mkdir ${USR_SAP}/hostctrl
		mkdir ${USR_SAP}/DAA
		mkdir ${USR_SAP}/trans
		mkdir ${USR_SAP}/SUM
		mkdir /BMS

		# SWAP Filesystem Creation
		pvcreate /dev/${SWAP_DISK}
		vgcreate vgswap /dev/${SWAP_DISK}
		lvcreate -L 20G -n lvswap vgswap
		mkswap /dev/vgswap/lvswap
	 	swapon /dev/vgswap/lvswap	
		
		#create /etc/fstab entries
		echo "# SAP Application Filesystem Entries" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapbin-lvsapbin ${USR_SAP} xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapbin-lvsaphostctrl /usr/sap/hostctrl xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapbin-lvsapdaa /usr/sap/DAA xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapbin-lvsaptrans /usr/sap/trans xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapbin-lvbms /BMS xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapmnt-lvsapmnt ${SAPMNT} xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapsum-lvsapsum /usr/sap/SUM xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/vgswap/lvswap  swap  swap 0 0" >> $FSTAB_FILE
		
		mount -a > /dev/null

     #validate /usr/sap and /sapmnt filesystems were created and mounted
     FS_USR_SAP=$(df -h | grep "$USR_SAP" | awk '{ print $NF }')
     FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

    if [ -z "$FS_USR_SAP" -o -z "$FS_SAPMNT" ]
    then
	#we did not successfully created the filesystems and mount points	
	echo 1
    else
	#we did successfully created the filesystems and mount points	
	echo 0
    fi	
}

set_asefilesystems() {
#create /usr/sap filesystem and mount /sapmnt

    SYBASEVOL=$(lsblk | grep ${SYB_ASE_DISK}) > /dev/null
    SYBDBDISK1=$(lsblk | grep ${SYB_DB_DISK_1}) > /dev/null
    SYBDBDISK2=$(lsblk | grep ${SYB_DB_DISK_2}) > /dev/null
    SYBDBDISK3=$(lsblk | grep ${SYB_DB_DISK_3}) > /dev/null
    SYBDBDISK4=$(lsblk | grep ${SYB_DB_DISK_4}) > /dev/null
    SYBLOGVOL=$(lsblk | grep ${SYB_LOG_DISK}) > /dev/null
		
	echo ${SYBDBDISK1}
	echo ${SYBDBDISK2}
	echo ${SYBDBDISK3}
	echo ${SYBDBDISK4}

    if [ -z "$SYBASEVOL" -o -z "$SYBDBDISK1" -o -z "$SYBDBDISK2" -o -z "$SYBDBDISK3" -o -z "$SYBDBDISK4" -o -z "$SYBLOGVOL" ]
    then
        echo "Exiting, can not create $SYBASEVOL or $SYBLOGVOL EBS volumes" 
        #signal the waithandler, 1=Failed
        /root/install/signalFinalStatus.sh 1 "Exiting, can not create $SYBASEVOL or $SYBDBVOL or $SYBLOGVOL volumes"
        set_cleanup_inifiles
        exit 1
    else
        mkdir $SYB > /dev/null
		
		# Create VGs and LVs for SYBASE Software Directories
		pvcreate /dev/$SYB_ASE_DISK
		vgcreate vgsybbin /dev/$SYB_ASE_DISK
		lvcreate -n lvsybmain -L 15G vgsybbin
		lvcreate -n lvsybbin -L 25G vgsybbin
		lvcreate -n lvsybdiag -L 10G vgsybbin
		lvcreate -n lvsybsec -L 2G vgsybbin
		lvcreate -n lvsybtmp -L 15G vgsybbin
		
		# Loop Through filesystem creation
		for i in lvsybmain lvsybbin lvsybdiag lvsybsec lvsybtemp
		do
			mkfs.xfs /dev/mapper/vgsybbin-${i}
		done
		
		# Mount Filesystems for Sybase DB Software location
		mount /dev/mapper/vgsybbin-lvsybmain ${SYB}
		mkdir ${SYBSIDFS} > /dev/null
		mount /dev/mapper/vgsybbin-lvsybbin ${SYBSIDFS}
		mkdir ${SYBSIDDATA1} ${SYBSIDDATA2} ${SYBSIDDATA3} ${SYBSIDDATA4} ${SYBSIDLOG1} > /dev/null
		mkdir ${SYBSIDFS}/sapdiag > /dev/null
		mkdir ${SYBSIDFS}/sybsecurity > /dev/null
		mkdir ${SYBSIDFS}/sybtemp > /dev/null
		mount /dev/mapper/vgsybbin-lvsybdiag ${SYBSIDFS}/sapdiag
		mount /dev/mapper/vgsybbin-lvsybsec ${SYBSIDFS}/sybsecurity
		mount /dev/mapper/vgsybbin-lvsybtemp ${SYBSIDFS}/sybtemp
		
		# Create VGs and LVs for SYBASE Data and Log Directories
		pvcreate /dev/${SYB_DB_DISK_1} /dev/${SYB_DB_DISK_2} /dev/${SYB_DB_DISK_3} /dev/${SYB_DB_DISK_4}
		vgcreate vgsapdata /dev/${SYB_DB_DISK_1} /dev/${SYB_DB_DISK_2} /dev/${SYB_DB_DISK_3} /dev/${SYB_DB_DISK_4}
	
		## Allocating 98% of space allocated to DB Filesystems
                DBFSSIZE="$(( ${DBSIZE}*98/100 ))"

		lvcreate -n lvsapdata1 -i 4 -I 256 -L ${DBFSSIZE}G vgsapdata
		lvcreate -n lvsapdata2 -i 4 -I 256 -L ${DBFSSIZE}G vgsapdata
		lvcreate -n lvsapdata3 -i 4 -I 256 -L ${DBFSSIZE}G vgsapdata
		lvcreate -n lvsapdata4 -i 4 -I 256 -L ${DBFSSIZE}G vgsapdata

		pvcreate /dev/${SYB_LOG_DISK}
		vgcreate vgsaplog /dev/${SYB_LOG_DISK}

		
		## Allocating 90% of space allocated to LOG Filesystems
                LOGFSSIZE="$(( ${LOGSIZE}*95/100 ))"
		lvcreate -n lvsaplog1 -L ${LOGFSSIZE}G vgsaplog
		
		# Loop Through Data filesystem creation
		for i in lvsapdata1 lvsapdata2 lvsapdata3 lvsapdata4
		do
			mkfs.xfs /dev/mapper/vgsapdata-${i}
		done
		
		# Loop Through Log filesystem creation

			mkfs.xfs /dev/mapper/vgsaplog-lvsaplog1
		
		# Mount the required Data and Log Filesystems
		mount /dev/mapper/vgsapdata-lvsapdata1 ${SYBSIDDATA1}
		mount /dev/mapper/vgsapdata-lvsapdata2 ${SYBSIDDATA2}
		mount /dev/mapper/vgsapdata-lvsapdata3 ${SYBSIDDATA3}
		mount /dev/mapper/vgsapdata-lvsapdata4 ${SYBSIDDATA4}
		mount /dev/mapper/vgsaplog-lvsaplog1 ${SYBSIDLOG1}
		
		#Add fstab Entries for all Newly Created FS
		echo " "
		echo "# SAP Database Filesystem Mounts" >> $FSTAB_FILE
		echo "/dev/mapper/vgsybbin-lvsybmain /sybase xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsybbin-lvsybbin ${SYBSIDFS} xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapdata-lvsapdata1 ${SYBSIDDATA1} xfs rw,seclabel,relatime,attr2,inode64,logbsize=256k,sunit=512,swidth=2048,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapdata-lvsapdata2 ${SYBSIDDATA2} xfs rw,seclabel,relatime,attr2,inode64,logbsize=256k,sunit=512,swidth=2048,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapdata-lvsapdata3 ${SYBSIDDATA3} xfs rw,seclabel,relatime,attr2,inode64,logbsize=256k,sunit=512,swidth=2048,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsapdata-lvsapdata4 ${SYBSIDDATA4} xfs rw,seclabel,relatime,attr2,inode64,logbsize=256k,sunit=512,swidth=2048,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsaplog-lvsaplog1 ${SYBSIDLOG1} xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsybbin-lvsybdiag /sybase/${SID}/sapdiag xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsybbin-lvsybsec /sybase/${SID}/sybsecurity xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		echo "/dev/mapper/vgsybbin-lvsybtemp /sybase/${SID}/sybtemp xfs rw,seclabel,relatime,attr2,inode64,noquota 0 0" >> $FSTAB_FILE
		mount -a > /dev/null
	fi
}

set_EFS() {
#mount up the EFS filesystem

	mkdir  $SAPMNT > /dev/null


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

            mount /sapmnt > /dev/null
            sleep 60
        fi

    fi

    #validate /sapmnt filesystems were created and mounted
    FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

    if [ -z "$FS_SAPMNT" ]
    then
	    #we did not successfully created the filesystems and mount points	
	    echo 1
    else
	    #we did successfully created the filesystems and mount points
        #we now share it out, call teh set_nfsexport function
        echo 0
    fi

}

set_update_cli() {
#update the aws cli
	 yum --disablerepo=saprepo install -y unzip
     curl "https://s3.amazonaws.com/aws-cli/awscli-bundle.zip" -o "awscli-bundle.zip"
	 unzip awscli-bundle.zip
	 sudo ./awscli-bundle/install -i /usr/local/aws -b /usr/local/bin/aws
}

echo
echo "Start set_update_cli @ $(date)"
echo
set_update_cli


set_s3_download() {
#download the s/w
          
          #download the media from the S3 bucket provided
          _S3_DL=$(aws s3 sync "s3://${S3_BUCKET}/${S3_BUCKET_KP}" "$SW_TARGET" 2>&1 >/dev/null | grep "download failed")
      	  cd "$SRC_INI_DIR" 
          cp *.params  "$SW_TARGET"
          chmod -R 755 $SW_TARGET > /dev/null 
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

set_dhcp() {
	#Create /etc/dhcp/dhclient.conf to generate the proper resolv.conf on reboot
	touch $DHCP
    echo "supersede domain-name-servers 165.89.14.56, 165.89.129.18, 165.89.129.6;" >> $DHCP
    echo "supersede domain-search \"bms.com\";" >> $DHCP
    echo "supersede domain-name \"net.bms.com ssc.bms.com bms.com aws.bms.com\";" >> $DHCP
    
     #restart network
     service network restart

}

set_hostname() {
#set and preserve the hostname

	hostnamectl set-hostname $SAPPAS_HOSTNAME

	#update /etc/hosts file
	echo "$IP  $SAPPAS_HOSTNAME.net.bms.com $SAPPAS_HOSTNAME" >> $HOSTS_FILE
	#service nscd restart

	#save our HOSTNAME to the master_etc_hosts file as well
	echo "$IP  $SAPPAS_HOSTNAME  #PAS Server#" >> $MASTER_HOSTS

	echo "$SAPPAS_HOSTNAME" > $HOSTNAME_FILE
	sed -i '/preserve_hostname/ c\preserve_hostname: true' $CLOUD_CFG

	#disable dhcp
	#_DISABLE_DHCP=$(set_dhcp)
	_DISABLE_DHCP=0
	#validate hostname and dhcp
	if [ "$(hostname)" == "$HOSTNAME" -a "$_DISABLE_DHCP" == 0 ]
	then
		echo 0
	else
		echo 1
	fi
}

set_nfsexport() {
#export the /sapmnt filesystem
     #need to check if /sapmnt filesystem files exists

     FS_SAPMNT=$(df -h | grep "$SAPMNT" | awk '{ print $NF }')

     if [ "$FS_SAPMNT" ]
     then
          #EXPORTS=$(echo $HOSTNAME | cut -c1-3)
	  #echo "$SAPMNT     $EXPORTS*(rw,no_root_squash,no_subtree_check)" >> /etc/exports
	  echo "$SAPMNT      *(rw,no_root_squash,no_subtree_check)" >> /etc/exports
          systemctl start nfs
		  systemctl enable nfs
          sleep 15
          exportfs -a
	  echo 0
     else
          #did not sucessfully export
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
	    exit 1
    fi
fi

#the cli needs to be updated in order to call ssm correctly


#test copy some logs

#recreat the SSM param store as encrypted
_MPINV=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $1}' | grep INVALID | wc -l)

_MPVAL=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $NF}' | wc -l)

while [ "$_MPVAL" -eq 0 -a "$_MPINV" -eq 0 ]
do
	echo "Waiting for SSM parameter store: $SSM_PARAM_STORE @ $(date)..."
	_MPINV=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $1}' | grep INVALID | wc -l)
	sleep 15
done

#Save the password
#_MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $NF}')
##The password used to be in $NF but moved to $4
_MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $4}')

#Delete the existing SSM param store
aws ssm delete-parameter --name $SSM_PARAM_STORE --region $REGION

#Recreate SSM param store
#Created an encrypted parameter_store for the master password
aws ssm put-parameter --name $SSM_PARAM_STORE  --type "SecureString" --value "$_MP" --region $REGION 

#Store the pass for the SAP param files
#MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $NF}')
##The password used to be in $NF but moved to $4
MP=$(aws ssm get-parameters --names $SSM_PARAM_STORE --with-decryption --region $REGION --output text | awk '{ print $4}')

echo
echo "Start set_install_jq @ $(date)"
echo
set_install_jq

echo
echo "Start set_tz @ $(date)"
echo
_SET_TZ=$(set_tz)

if [ "$_SET_TZ" == 0 ]
then
     echo "Success, current TZ = $_CURRENT_TZ"
else
     echo "FAILED, current TZ = $_CURRENT_TZ"
     /root/install/signalFinalStatus.sh 1 "FAILED, current TZ = $_CURRENT_TZ"
     exit
fi

_SET_AWSDP=$(set_awsdataprovider)

if [ "$_SET_AWSDP" == 0 ]
then
     echo "Successfully installed AWS Data Provider"
else
     echo "FAILED to install AWS Data Provider...exiting"
     /root/install/signalFinalStatus.sh 1 "FAILED to install AWS Data Provider...exiting"
     exit
fi


echo "Starting OSS configuration"

_SET_OSS=$(set_oss_configs)


echo "Mapping EBS Volumes for Device Parameters"
## One Liner for nvme EBS volume mapping
yum install -y nvme-cli
devmapfile="/tmp/devmapfile"
for i in {0..10} ;  do  
    nvme id-ctrl -H -v /dev/nvme${i}n1 | grep "0000:" | awk '{print "export "$18}' | tr --delete . | tr --delete \"; echo "=\"nvme${i}n1\""; done | awk 'NR%2{printf "%s",""$0;next;}"1"' | sort -k 1.19 >> ${devmapfile}

## source devmapfile in the deployment code that will map "/dev/sda" device names in nvme format (/dev/nvme0n1)
chmod +x ${devmapfile}
source ${devmapfile}

### Resetting Device Parameters
USR_SAP_DISK="${sdb}"
SAPMNT_DISK="${sdc}"
SYB_DB_DISK_1="${sdd}"
SYB_DB_DISK_2="${sde}"
SYB_DB_DISK_3="${sdf}"
SYB_DB_DISK_4="${sdg}"
SYB_LOG_DISK="${sdh}"
SYB_ASE_DISK="${sdi}"
SWAP_DISK="${sdj}"
SUM_DISK="${sdk}"

#We need to determine if we are using EFS or a local /sapmnt
if [ "$EFS" == "Yes" ]
then
    echo
    echo "Start set_EFS @ $(date)"
    echo
    _SET_EFS=$(set_EFS)
    _SAPMNT=$(df -h $SAPMNT | awk '{ print $NF }' | tail -1)

    if [ "$_SAPMNT" == "$SAPMNT"  ]
    then
	    echo "Successfully setup /sapmnt"
    else
	    echo "Failed to mount $SAPMNT...exiting"
	    #signal the waithandler, 1=Failed
       	    /root/install/signalFinalStatus.sh 1 "Failed to _SET_EFS for /sapmnt with EFS filesystem: $EFS_MP"
	    set_cleanup_ascsinifile
	    exit 1
    fi
else
    echo
    echo "Start set_filesystems @ $(date)"
    echo
    _SET_FS=$(set_filesystems)
    _SET_DBFS=$(set_asefilesystems)
    echo "$_SET_FS"
    echo "$_SET_DBFS"
        echo "Successfully created $USR_SAP and $SAPMNT and DB Filesystems"
        echo
        echo "Start set_nfsexport @ $(date)"
        echo
        _SET_NFS=$(set_nfsexport)
        SHOWMOUNT=$(showmount -e | wc -l)
fi

echo
echo "Start set_s3_download @ $(date)"
echo
_SET_S3=$(set_s3_download)

echo
echo "Start set_hostname @ $(date)"
echo
_SET_HOSTNAME=$(set_hostname)

echo
echo "Start set_install_ssm @ $(date)"
echo
set_install_ssm

## Extract SAP Binaries

## ASE
mkdir /sapmnt/NW75/ASE/
unzip /sapmnt/NW75/51053053_1.ZIP -d /sapmnt/NW75/
chmod -R 777  /sapmnt/NW75/

## EXPORTS
##TDB
## mkdir /sapmnt/NW75/EXPORTS
## unrar x /sapmnt/NW75/xxxx.exe --<destination>
## chmod -R 777 /sapmnt/NW75/EXPORTS


###Execute sapinst###

if [ "$INSTALL_SAP" == "No" ]
then
	echo "Completed setting up SAP App Server Infrastrucure."
	echo "Exiting as the option to install SAP software was set to: $INSTALL_SAP"
	#signal the waithandler, 0=Success
	/root/install/signalFinalStatus.sh 0 "Finished. Exiting as the option to install SAP software was set to: $INSTALL_SAP"
        exit 0
fi

#**Install the ASCS and DB Instances**

set_netweaverstandaloneaseinifile

SIDADM="${SID,,}adm"

#Install the ASCS and DB Instances

umask 006

cd $SAPINST
sleep 5

#support multilple NW versions

# Workaround for csh error during sapinst ( will add the package in Repo for future Deployment)
yum install -y csh --disablerepo=saprepo

echo "Installing the PAS and DB instance"
./sapinst SAPINST_INPUT_PARAMETERS_URL="$PAS_Standalone_ASE_INI_FILE" SAPINST_EXECUTE_PRODUCT_ID="NW_ABAP_OneHost:NW750.SYB.ABAP" SAPINST_USE_HOSTNAME="$SAPPAS_HOSTNAME" SAPINST_SKIP_DIALOGS="true" SAPINST_SLP_MODE="false" SAPINST_GUI_HOSTNAME="$SAPPAS_HOSTNAME"

### fix for Bug with swpm (sapnote 1902347 - Unable to start database with startsap - SYB ASE)
/sapmnt/${SID}/exe/uc/linuxx86_64/saproot.sh ${SID}


su - "$SIDADM" -c "stopsap"
sleep 5
su - "$SIDADM" -c "startsap"
sleep 15

#test if SAP is up
_SAP_UP=`/usr/sap/$SID}/SYS/exe/uc/linuxx86_64/sapcontrol -nr ${SAPInstanceNum} -function GetProcessList | grep disp+work | awk -F ',' '{print $3}'`

echo "This is the value of SAP_UP: $_SAP_UP"


if [ "$_SAP_UP" == "GREEN" ]
then
	#create the PAS done file
	touch "$PAS_DONE"
	#signal the waithandler, 0=Success
	/root/install/signalFinalStatus.sh 0 "SAP successfully install."
			set_cleanup_inifiles
	#create the /etc/sap-app-quickstart file
	touch /etc/sap-app-quickstart
	chmod 1777 /tmp
	mv /var/run/dbus/system_bus_socket.bak /var/run/dbus/system_bus_socket
	else
	echo "SAP PAS failed to install...exiting"
	#signal the waithandler, 1=Failed
	/root/install/signalFinalStatus.sh 1 "SAP PAS and DB failed to install...exiting"
			set_cleanup_inifiles
	exit
fi

