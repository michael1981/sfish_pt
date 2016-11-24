#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(27524);
  script_version("$Revision: 1.19 $");

  script_name(english:"Microsoft Office Detection");
  script_summary(english:"Detects Microsoft Office");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote Windows host contains an office suite.'
  );

  script_set_attribute(
    attribute:'description',
    value:'Microsoft Office is installed on the remote host.'
  );

  script_set_attribute(
    attribute:'solution',
    value:'n/a'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://office.microsoft.com'
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_end_attributes();
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("smb_nt_ms02-031.nasl");
  if ( NASL_LEVEL >= 3206 ) script_require_ports("SMB/Office/Word/Version", "SMB/Office/Excel/Version", "SMB/Office/PowerPoint/Version");
  exit(0);
}


# version, sp, file version

i = 0;

# 2000 SP0
all_office_versions[i++] = make_list("Word", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("Excel", "2000", 0, "9.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2000", 0, "9.0.0.0");

# 2000 SP1 - no information

# 2000 SP2
all_office_versions[i++] = make_list("Word", "2000", 2, "9.0.0.4527");
all_office_versions[i++] = make_list("Excel", "2000", 2, "9.0.0.4430");
all_office_versions[i++] = make_list("PowerPoint", "2000", 2, "9.0.0.4527");

# 2000 SP3
all_office_versions[i++] = make_list("Word", "2000", 3, "9.0.0.6926");
all_office_versions[i++] = make_list("Excel", "2000", 3, "9.0.0.6627");
all_office_versions[i++] = make_list("PowerPoint", "2000", 3, "9.0.0.6620");

# XP SP0
all_office_versions[i++] = make_list("Word", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("Excel", "XP", 0, "10.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 0, "10.0.0.0");

# XP SP1
all_office_versions[i++] = make_list("Word", "XP", 1, "10.0.3416.0");
all_office_versions[i++] = make_list("Excel", "XP", 1, "10.0.3506.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 1, "10.0.3506.0");

# XP SP2
all_office_versions[i++] = make_list("Word", "XP", 2, "10.0.4219.0");
all_office_versions[i++] = make_list("Excel", "XP", 2, "10.0.4302.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 2, "10.0.4205.0");

# XP SP3
all_office_versions[i++] = make_list("Word", "XP", 3, "10.0.6612.0");
all_office_versions[i++] = make_list("Excel", "XP", 3, "10.0.6501.0");
all_office_versions[i++] = make_list("PowerPoint", "XP", 3, "10.0.6501.0");

# 2003 SP0
all_office_versions[i++] = make_list("Word", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("Excel", "2003", 0, "11.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 0, "11.0.0.0");

# 2003 SP1
all_office_versions[i++] = make_list("Word", "2003", 1, "11.0.6359.0");
all_office_versions[i++] = make_list("Excel", "2003", 1, "11.0.6355.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 1, "11.0.6361.0");

# 2003 SP2
all_office_versions[i++] = make_list("Word", "2003", 2, "11.0.6568.0");
all_office_versions[i++] = make_list("Excel", "2003", 2, "11.0.6560.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 2, "11.0.6564.0");

# 2003 SP3
all_office_versions[i++] = make_list("Word", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("Excel", "2003", 3, "11.0.8169.0");
all_office_versions[i++] = make_list("PowerPoint", "2003", 3, "11.0.8169.0");

# 2007 SP0
all_office_versions[i++] = make_list("Word", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("Excel", "2007", 0, "12.0.0.0");
all_office_versions[i++] = make_list("PowerPoint", "2007", 0, "12.0.0.0");

# 2007 SP1
all_office_versions[i++] = make_list("Word", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("Excel", "2007", 1, "12.0.6215.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 1, "12.0.6215.1000");

# 2007 SP2
all_office_versions[i++] = make_list("Word", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("Excel", "2007", 2, "12.0.6425.1000");
all_office_versions[i++] = make_list("PowerPoint", "2007", 2, "12.0.6425.1000");

function check_version(v1, v2)
{
 local_var j;

 v1 = split(v1, sep:".", keep:FALSE);
 v2 = split(v2, sep:".", keep:FALSE);

 for (j=0; j<4; j++)
 {
  if (int(v1[j]) > int(v2[j]))
    return 1;
  else if (int(v1[j]) < int(v2[j]))
    return -1;
 }

 return 0;
}

version = NULL;
installed_office_versions = make_array();

products = make_list( "Word", "Excel", "PowerPoint" );
foreach product (products)
{
 kb = get_kb_list( string( 'SMB/Office/', product, '/Version' ) );
 if ( isnull( kb ) )
  continue;
 kb = make_list( kb );
 foreach ver( kb )
 {
  report_str = string('  - ', product, ' : ', ver, '\n');
  prod_version = split( ver, sep:'.', keep:FALSE );
  if ( installed_office_versions[ prod_version[ 0 ] ] )
   installed_office_versions[ prod_version[ 0 ] ] += report_str;
  else
   installed_office_versions[ prod_version[ 0 ] ] = report_str;
 }
}

kb_blob = 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/{*}/DisplayName';
installed_products_by_uuid = get_kb_list( kb_blob );

foreach uuid ( keys( installed_products_by_uuid ) )
{
 if ( ( installed_products_by_uuid[ uuid ] =~ '^Microsoft Office (2000|XP|[a-zA-Z ]*?(Edition|20[01][0-9]))' ) &&
      ( ! ereg( pattern:"(Media Content|Get Started|Proof|MUI|Communicator|InfoPath|Web Components)",
                  string:installed_products_by_uuid[ uuid ], icase:TRUE ) ) )
 {
  kb = get_kb_item( str_replace( string:uuid, find:'DisplayName', replace:'DisplayVersion' ) );
  if ( isnull( kb ) )
   continue;
  office_version = split( kb, sep:'.', keep:FALSE );

  prod_detail = installed_office_versions[ office_version[ 0 ] ];

  if ( prod_detail )
  {
   len = max_index(all_office_versions);
   for (i=0; i<len; i++)
   {
    info = all_office_versions[i];
    if (check_version(v1:kb, v2:info[3]) >= 0)
      version = i;
   }
   info = all_office_versions[version];

   report_detail = string( '\nThe remote host has the following Microsoft Office ', info[1], ' Service Pack ',
                           info[2],' component' );
   if ( max_index( split( prod_detail ) ) > 1 )
    report_detail += 's';
   report_detail += ' installed :\n\n';
   installed_office_versions[ office_version[ 0 ] ] = report_detail + prod_detail;
   set_kb_item(name:"SMB/Office/Version", value:info[1]);
   set_kb_item(name:"SMB/Office/SP", value:info[2]);
  }
 }
}


if (max_index(keys(installed_office_versions)) == 0)
 exit(0, "No instances of Office were found.");

report = NULL;
foreach key ( keys( installed_office_versions ) )
 report += installed_office_versions[ key ];

security_note(port:0, extra:report);
