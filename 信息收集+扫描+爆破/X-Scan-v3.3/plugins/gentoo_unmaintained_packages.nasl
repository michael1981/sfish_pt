#
# This script is (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(24017);
 script_version("$Revision: 1.5 $");

 script_set_attribute(attribute:"synopsis", value:
"The remote operating system contains obsolete software" );
 script_set_attribute(attribute:"description", value:
"The remote Gentoo system contains several packages or versions 
which have been marked as obsolete and have been removed from 
the portage tree.
These versions are therefore unmaintained, which means that if
any security flaw is found in them, no patch will be made 
available.

In addition to this, these packages might break after a library 
upgrade and it will be impossible to recompile them." );
 script_set_attribute(attribute:"solution", value:
"Remove or upgrade those packages." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P" );

script_end_attributes();

 script_copyright(english: "Copyright (C) 2007-2009 Tenable Network Security, Inc.");
 script_name(english: "Unmaintainted Gentoo packages");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list', 'Host/Gentoo/ebuild-list');
 script_summary(english: 'Find obsolete Gentoo packages that cannot be installed any more');
 exit(0);
}

include('global_settings.inc');

installed = get_kb_item('Host/Gentoo/qpkg-list');
maintained = get_kb_item('Host/Gentoo/ebuild-list');

# 
# Debug only
# function exec(cmd)
# {
#  return pread(cmd: "/bin/sh", argv: make_list("sh", "-c", cmd));
# }
# 
# installed = exec(cmd: 'find /var/db/pkg/ -mindepth 2 -maxdepth 2 -printf "%P\\n"');
# maintained = exec(cmd: "find /usr/portage/ -wholename '/usr/portage/*-*/*.ebuild' | sed 's,/usr/portage/\([^/]*\)/.*/\([^/]*\)\.ebuild$,\1/\2,'");
# 

if (isnull(installed) || isnull(maintained)) exit(0);

bad_l = ''; old_l = ''; obs_l = '';

maintained_v = sort(split(maintained, keep: 0));
maintained = NULL;	# Free memory

installed_v = sort(split(installed, keep: 0));
installed = NULL;

i1 = 0; i2 = 0; n1 = max_index(maintained_v); n2 = max_index(installed_v);
all = 0; bad = 0;

prev_m = maintained_v[0];	# So that it can be parsed

for (i2 = 0; i2 < n2; i2 ++)
{
 # There is no software in a "virtual" package
 # -MERGING-* & lockfiles are artefacts
 if (! match(string: installed_v[i2], pattern: 'virtual/*') &&
     ! match(string: installed_v[i2], pattern: '*/-MERGING-*') &&
     ! match(string: installed_v[i2], pattern: '*/*.portage_lockfile') )
 {
  while (maintained_v[i1] < installed_v[i2])
  {
   prev_m = maintained_v[i1];
   i1 ++;
  }

  if (maintained_v[i1] != installed_v[i2])
  {
   pat = '^([a-z0-9]+-[a-z0-9]+/[^0-9][a-z0-9+_-]+)-[0-9].*$';
   iv = eregmatch(string: installed_v[i2], pattern: pat, icase: 1);
   mv = eregmatch(string: maintained_v[i1], pattern: pat, icase: 1);
   pv = eregmatch(string: prev_m, pattern: pat, icase: 1);

   if (! isnull(iv)  && ! isnull(mv) && ! isnull(pv))
    if (iv[1] == mv[1] || iv[1] == pv[1])
     old_l += installed_v[i2] + '\n';
    else
     obs_l += installed_v[i2] + '\n';
   else
   {
    debug_print('Cannot parse ', installed_v[i2], ' or ', maintained_v[i1], ' or ', prev_m);
    bad_l += installed_v[i2] + '\n';
   }
   bad ++;
  }
  all ++;
 }
}

if (bad > 0) 
{
 desc = '';
 if (strlen(obs_l) > 0)
  desc = strcat(desc, 'The following packages are not maintained any more:\n', obs_l, '\n');
 if (strlen(old_l) > 0)
  desc = strcat(desc, 'The following packages should be updated:\n', old_l, '\n');
 if (bad_l > 0)
  desc = strcat(desc, 'The following obsolete packages were found:\n', bad_l, '\n');
  security_warning(port: 0, extra: desc);
}
debug_print('Found ', bad, ' obsolete packages among ', all, ' packages\n');
