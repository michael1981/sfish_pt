#
# This NASL script was written by Martin O'Neal of Corsaire (http://www.corsaire.com)
# 
# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.
# 

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, output formatting, family change (8/22/09)

include("compat.inc");

if(description)
{
	script_id(19510);
	script_version ("$Revision: 1.7 $");
	script_cve_id("CVE-2004-0952");
	script_bugtraq_id(14571);
        script_xref(name:"OSVDB", value:"18750");

	script_name(english:"HP-UX Ignite-UX TFTP Service Remote File Manipulation");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote TFTP daemon has an arbitrary file upload vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a vulnerable version of the HP Ignite-UX
application installed that exposes a world-writeable directory to
anonymous TFTP access.  A remote attacker could exploit this to
upload arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://research.corsaire.com/advisories/c041123-002.txt"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate vendor patch."
  );
  script_set_attribute(
    attribute:"cvss_vector",
    value:"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P"
  );
  script_end_attributes();

	script_summary(english:"Determines if the remote host has writeable directories exposed via TFTP (HP Ignite-UX)");
	script_category(ACT_DESTRUCTIVE_ATTACK); # Intrusive
	script_copyright(english:"This NASL script is Copyright 2005-2009 Corsaire Limited.");
	script_family(english:"Misc.");
	script_dependencies("tftpd_backdoor.nasl");
	script_require_keys("Services/udp/tftp");
	script_exclude_keys('tftp/backdoor'); # Not wise but quicker
 	exit(0);
}



############## declarations ################




port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);



############## script ################

include("tftp.inc");

# initialise test
file_name='/var/opt/ignite/nessus_tftp_test_'+rand();
if(tftp_put(port:port,path:file_name))
	security_warning(port:port,proto:"udp");

