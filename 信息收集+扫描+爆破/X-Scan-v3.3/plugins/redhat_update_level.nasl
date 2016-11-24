#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#
# This script is released under the GNU GPLv2

if ( ! defined_func("bn_random") ) exit(0);

include("compat.inc");

if(description)
{
 script_id(14657);
 script_version ("$Revision: 1.12 $");
 name["english"] = "RedHat update level";
 
 script_name(english:name["english"]);
 
 script_set_attribute(
  attribute:"synopsis",
  value:"The remote Red Hat server is out-of-date."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote Red Hat server is missing the latest bugfix update
package.  This may leave the system open to multiple vulnerabilities."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://www.redhat.com/security/notes/"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Apply the latest update."
 );
 script_set_attribute(
  attribute:"cvss_vector",
  value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C"
 );
 script_end_attributes();
 
 summary["english"] = "Check for RedHat update level"; 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 David Maciejak");
 
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/release");
 exit(0);
}


#the code

#here the list of redhat version/last update level

lastupdate[2]=7;
lastupdate[3]=9;
lastupdate[4]=8;

buf=get_kb_item("Host/RedHat/release");
if (!buf) exit(0);
v = eregmatch(string: buf, pattern: "Update ([0-9]+)");
if (isnull(v)) exit(0);
updatelevel=int(v[1]);

release=NULL;
if(egrep(pattern:"Red Hat Enterprise Linux.*release 3", string:buf) ) release=3;
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 2\.1", string:buf) ) release=2; 
else if (egrep(pattern:"Red Hat.*(Enterprise|Advanced).*release 4", string:buf) ) release=4;

if (isnull(release)) exit(0);

if (updatelevel < lastupdate[release])
{
str="
The remote host is missing a RedHat update package.
Maintenance level "+updatelevel+" is installed.
The latest available is "+lastupdate[release]+".

You should install this package for your system to be up-to-date.
";
 security_hole(port:0, extra:str);
 exit(0);
}

