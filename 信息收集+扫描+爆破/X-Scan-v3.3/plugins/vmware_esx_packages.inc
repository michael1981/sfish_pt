#
# (C) Tenable Network Security, Inc.
#
# @NOGPL@
#
# $Revision: 1.1 $
#

include('global_settings.inc');

global_var	esx_pkg_l, esx_version, newest_bundle;
esx_pkg_l = NULL; esx_version = NULL; newest_bundle = NULL;

function init_esx_check(date)
{
  global_var	esx_pkg_l, esx_version, newest_bundle;

  if (! esx_pkg_l)
  {
    esx_pkg_l = get_kb_item("Host/VMware/esxupdate");
    if (! esx_pkg_l) exit(1, "List of vmware ESX packages is empty");
  }
  if (! esx_version)
  {
    esx_version = get_kb_item("Host/VMware/version");
    if (! esx_version)
      exit(1, "Version of vmware ESX is unknown");
  }
  if (! newest_bundle)
    newest_bundle = get_kb_item("Host/VMware/NewestBundle");
  if (newest_bundle && date <= newest_bundle)
  {
    debug_print('Advisory is older (', date, ') than the last installed bundle (', newest_bundle, ')\n');
    exit(0, "Advisory is older than the last installed bundle");
  }
}

function esx_check(ver, patch)
{
  local_var	v, date;

  if (ver != esx_version) return 0;
    debug_print('P=', patch, ' N=', newest_bundle, '\n');
  if (newest_bundle)
  {
    # Extract Year & Month from patch ID
    v = eregmatch(string: patch, pattern: "^ESXi?[0-9]+-(20[0-9][0-9])([0-9][0-9])[0-9]+-[A-Z]+$");
    date = strcat(v[1], '-', v[2], '-01');
    if (date <= newest_bundle)
    {
      debug_print('Patch ', patch, ' is older than the last installed bundle\n');
      return 0;
    }
  }
  if (egrep(pattern: '^[ \t]*'+patch+'[ \t]', string: esx_pkg_l))
  {
   debug_print('Patch ', patch, ' is installed on ', ver, '\n');
   return 0;
  }
#  debug_print('Patch ', patch, ' is missing on ', ver, '\n');
  return 1;
}
