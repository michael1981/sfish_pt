#
# (C) Tenable Network Security, Inc.
#

# Credits:
# Philippe de Brito (Le Mamousse) discovered the flaw and sent his exploit.
#


include("compat.inc");

if(description)
{
 script_id(11221);
 script_version("$Revision: 1.9 $");
 script_xref(name:"OSVDB", value:"52990");

 script_name(english:"Pages Pro filenote Parameter Traversal Arbitrary File Modification");
 
 script_set_attribute(attribute:"synopsis", value:
"It may be possible read and modify arbitrary files from the
remote system." );
 script_set_attribute(attribute:"description", value:
"A security vulnerability in the 'Pages Pro' allows anybody
to read or modify files that would otherwise be inaccessible
using a directory traversal attack. A cracker may use this 
to read or write sensitive files or even make a phone call." );
 script_set_attribute(attribute:"see_also", value:"http://www.certa.ssi.gouv.fr/site/CERTA-2002-ALE-007/index.html.2.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade it (version 2003) or uninstall this product." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:P" );

script_end_attributes();
 
 script_summary(english:"Pages Pro CD directory traversal");
 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2002-2009 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8100);
 exit(0);
}

# 

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8100);
foreach port (ports)
{
 file[0] = "windows/win.ini";
 file[1] = "winnt/win.ini";

 for (i = 0; file[i]; i = i + 1)
 { 
  u = string("/note.txt?F_notini=&T_note=&nomentreprise=blah&filenote=../../",
             file[i]);
  if(check_win_dir_trav(port: port, url:u))
  {
    security_hole(port);
    break;
  }
 }
}

