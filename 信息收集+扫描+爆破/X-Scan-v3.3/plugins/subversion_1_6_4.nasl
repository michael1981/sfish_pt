#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40620);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_xref(name:"OSVDB", value:"56856");
  script_xref(name:"Secunia", value:"36184");

  script_name(english:"Subversion < 1.6.4 libsvn_delta Library Binary Delta svndiff Stream Parsing Multiple Overflows");
  script_summary(english:"Checks Subversion Client/Server version"); 

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple heap
overflow issues." );

  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Client or Server is affected by
multiple heap overflow issues. 

Specifically, the 'libsvn_delta' library fails to perform sufficient
boundary checks before processing certain svndiff streams.  An
attacker with commit access to a vulnerable Subversion server could
exploit this vulnerability from a Subversion client to trigger a heap
overflow on the server.  Typically such an attack would result in a
denial of service condition or arbitrary code execution on the remote
server. 

An attacker could also trigger this issue from a rogue Subversion
server on a Subversion client in response to a checkout or update
request." );

  script_set_attribute(attribute:"see_also", value:"http://svn.haxx.se/dev/archive-2009-08/0107.shtml" );
  script_set_attribute(attribute:"see_also", value:"http://svn.haxx.se/dev/archive-2009-08/0108.shtml" );
  script_set_attribute(attribute:"see_also", value:"http://subversion.tigris.org/security/CVE-2009-2411-advisory.txt" );

  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Client/Server 1.6.4 or later.

If using Subversion Client/Server 1.5.x, make sure 
you are using version CollabNet binaries 1.5.7 or later." );

  script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C" );

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/19");

  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("SMB/Subversion/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");

# Check each client install.

c_installs = get_kb_list("SMB/Subversion/Client/*");

info = NULL;

if(!isnull(c_installs))
{
  foreach install (keys(c_installs))
  { 
    version = install - "SMB/Subversion/Client/";
    matches = eregmatch(pattern:"^([a-zA-Z]+)/([0-9.]+$)",string:version);
    provider = matches[1];
    version = matches[2];
    
    if(!isnull(provider) && !isnull(version))
    {
    ver = split(version, sep:".", keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      v[i] = int(ver[i]);

    if((v[0] < 1 ) ||
     ( v[0] == 1 && v[1] < 5 ) ||
     ( v[0] == 1 && v[1] == 5 && v[2] < 7 ) ||
     # Only CollabNet provides updated 1.5.7 binaries 
     ( v[0] == 1 && v[1] == 5 && v[2] == 7  && "CollabNet" >!< provider ) || 
     ( v[0] == 1 && v[1] == 6 && v[2] < 4 )
     )
      info += ' Subversion Client - Version ' + version + 
        ' packaged with ' + provider + ' is installed under \n  ' + 
         c_installs[install] + '\n\n';
    }
  }
}

# Check each Server install.

if(get_kb_list("Services/subversion") || report_paranoia > 1)
{
  s_installs = get_kb_list("SMB/Subversion/Server/*");

  if(!isnull(s_installs))
  {
    foreach install (keys(s_installs))
    {
      version = install - "SMB/Subversion/Server/";
      matches = eregmatch(pattern:"^([a-zA-Z]+)/([0-9.]+$)",string:version);
      provider = matches[1]; 
      version = matches[2]; 
    
      if(!isnull(provider) && !isnull(version))
      {
        ver = split(version, sep:".", keep:FALSE);
        for (i=0; i<max_index(ver); i++)
          v[i] = int(ver[i]);

         if((v[0] < 1 ) ||
          ( v[0] == 1 && v[1] < 5 ) ||
          ( v[0] == 1 && v[1] == 5 && v[2] < 7 ) ||
          # Only CollabNet provides updated 1.5.7 binaries 
          ( v[0] == 1 && v[1] == 5 && v[2] == 7  && "CollabNet" >!< provider) ||
          ( v[0] == 1 && v[1] == 6 && v[2] < 4 )
        )
        info += ' Subversion Server - Version ' + version + 
        ' packaged with ' + provider + ' is installed under \n  ' + 
         s_installs[install] + '\n\n';
      }
    }
  }
}

# Report if any were found to be vulnerable.

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s of Subversion are";
    else s = " of Subversion is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed :\n",
      "\n",
      info
    );
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
