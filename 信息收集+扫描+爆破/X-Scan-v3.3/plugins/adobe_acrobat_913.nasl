#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');


if (description)
{
  script_id(40806);
  script_version('$Revision: 1.3 $');

  script_cve_id('CVE-2009-1862');
  script_bugtraq_id(35759);
  script_xref(name:'OSVDB', value:'56282');

  script_name(english:'Adobe Acrobat < 9.1.3 Flash Handling Unspecified Arbitrary Code Execution');
  script_summary(english:'Checks version of Adobe Acrobat');

  script_set_attribute(
    attribute:'synopsis',
    value:string(
      "The version of Adobe Acrobat on the remote Windows host is affected by\n",
      "a memory corruption vulnerability."
    )
  );
  script_set_attribute(
    attribute:'description',
    value:string(
      'The version of Adobe Acrobat 9 installed on the remote host is earlier\n',
      'than 9.1.3.  Such versions are reportedly affected by a memory corruption\n',
      'vulnerability that could potentially lead to code execution'
    )
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.adobe.com/support/security/bulletins/apsb09-10.html'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to Adobe Acrobat 9.1.3 or later.'
  );
  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C'
  );

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/07/28' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/07/30' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/08/28' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:'This script is Copyright (C) 2009 Tenable Network Security, Inc.');

  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');

  exit(0);
}


include('global_settings.inc');


version = get_kb_item('SMB/Acrobat/Version');
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if  ( ver[0] == 9 && ( ver[1] < 1 || (ver[1] == 1 && ver[2] < 3) ) )
{
  version_ui = get_kb_item('SMB/Acrobat/Version_UI');
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report = string(
      '\n',
      '  Path              : ', path, '\n',
      '  Installed version : ', version_ui, '\n',
      '  Fix               : 9.1.3\n'
    );
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "Acrobat "+version+" is not affected.");
