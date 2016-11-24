#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14235);
 script_cve_id("CVE-2004-2491");
 script_bugtraq_id(10810, 10517);

 script_xref(name:"OSVDB", value:"8317"); 

 script_version("$Revision: 1.8 $");

 script_name(english:"Opera web browser URI obfuscation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has application that may allow arbitrary 
code execution on the remote system." );
 script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is 
vulnerable to a flaw wherein a remote attacker can obscure 
the URI, leading the user to believe that he/she is 
accessing a trusted resource. To exploit this issue, an 
attacker would need to set up a rogue web site, then 
entice a local user to visit the site.  Successful 
exploitation would enable the attacker to execute arbitrary
code on this host." );
 script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/fulldisclosure/2004-07/1056.html" );
 script_set_attribute(attribute:"solution", value:
"Install Opera 7.54 or newer." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

script_end_attributes();

 script_summary(english:"Check version of Opera for URI obfuscation bug");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security, Inc.");
 family["english"] = "Windows";
 script_family(english:family["english"]);
 
 script_dependencies("opera_installed.nasl");
 script_require_keys("SMB/Opera/Version");

 exit(0);
}


include("global_settings.inc");


version_ui = get_kb_item("SMB/Opera/Version_UI");
version = get_kb_item("SMB/Opera/Version");
if (isnull(version)) exit(0);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] < 54)
)
{
  if (report_verbosity && version_ui)
  {
    report = string(
      "\n",
      "Opera ", version_ui, " is currently installed on the remote host.\n"
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
