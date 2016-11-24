#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25251);
  script_version("$Revision: 1.8 $");

  script_name(english:"OS Identification : Unix uname");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system
based on the response returned by 'uname -a'" );
 script_set_attribute(attribute:"description", value:
"This script attempts to identify the Operating System type and 
version by looking at the data returned by 'uname -a'." );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

script_end_attributes();

  script_summary(english:"Determines the remote operating system");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_family(english:"General");
  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/uname");
  exit(0);
}


uname = get_kb_item("Host/uname");
if ( ! uname ) exit(0);

confidence = 100;
set_kb_item(name:"Host/OS/uname/Fingerprint", value:uname);
array = eregmatch(pattern:"^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*).*", string:uname);
if ( isnull(array) ) exit(0);

if ( array[1] == "Linux" )
 {
 os = "Linux Kernel " + array[3];
 confidence --; # we don't have the distribution
 }
 

else if ( array[1] == "Darwin" )
{
 os = get_kb_item("Host/MacOSX/Version");
 if (isnull(os))
 {
  num = split(array[3], sep:".", keep:FALSE);
  os = "Mac OS X 10." + string(int(num[0]) - 4) + "." + num[1];
 }
}
else if ( array[1] == "SunOS" )
{
 num = split(array[3], sep:".", keep:FALSE);
 os = "Solaris " + num[1];
 if ( "sparc" >< uname ) os += " (sparc)";
 else if ( "i386" >< uname ) os += " (i386)";
}
else if ( array[1] == "AIX" )
{
 # AIX servername 3 5 000B8AC4D600 
 os = strcat("AIX ", array[4], ".", array[3]);
}
else { os = array[1] + " " + array[3]; confidence -= 10; }


set_kb_item(name:"Host/OS/uname", value:os);
set_kb_item(name:"Host/OS/uname/Confidence", value:confidence);
set_kb_item(name:"Host/OS/uname/Type", value:"general-purpose");

