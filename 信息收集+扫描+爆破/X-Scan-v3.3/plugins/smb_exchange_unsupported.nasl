#
# (C) Tenable Network Security
#



include("compat.inc");

if(description)
{
 script_id(22313);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "Unsupported version of Microsoft Exchange Server";
 
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of Microsoft Exchange which is not
supported by Microsoft any more." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Exchange Server which is
not supported any more. As a result, it may contain critical vulnerabilities
which have not been patched." );
 script_set_attribute(attribute:"solution", value:
"Apply the relevant service packs from Microsoft to upgrade to a supported
version." );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/gp/lifesupsps" );
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 
 summary["english"] = "Determines the remote version of Exchange";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Exchange/Version");
 script_require_ports(139, 445);
 exit(0);
}


ver = get_kb_item("SMB/Exchange/Version");
if ( ! ver ) exit(0);

sp = get_kb_item("SMB/Exchange/SP");
if ( isnull(sp) ) sp = 0;
report = "";

# Exchange 2000
if ( ver == 60 && sp < 3 ) {

 report = 
'The remote host is running Microsoft Exchange Server 2000 SP' + sp + '\n' +
'Apply Service Pack 3 to be up-to-date';
 security_warning(extra:report);
}

# Exchange 2003
if ( ver == 65 && sp < 1 ) {
 report = 
'The remote host is running Microsoft Exchange Server 2003 SP' + sp + '\n' +
'Apply Service Pack 2 to be up-to-date';
 security_warning(extra:report);
}
 
