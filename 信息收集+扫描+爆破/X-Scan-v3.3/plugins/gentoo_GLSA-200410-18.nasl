# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200410-18.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(15527);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200410-18");
 script_cve_id("CVE-2004-0967");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200410-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200410-18
(Ghostscript: Insecure temporary file use in multiple scripts)


    The pj-gs.sh, ps2epsi, pv.sh and sysvlp.sh scripts create temporary files
    in world-writeable directories with predictable names.
  
Impact

    A local attacker could create symbolic links in the temporary files
    directory, pointing to a valid file somewhere on the filesystem. When an
    affected script is called, this would result in the file to be overwritten
    with the rights of the user running the script, which could be the root
    user.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    Ghostscript users on all architectures except PPC should upgrade to the
    latest version:
    # emerge sync
    # emerge -pv ">=app-text/ghostscript-esp-7.07.1-r7"
    # emerge ">=app-text/ghostscript-esp-7.07.1-r7"
    Ghostscript users on the PPC architecture should upgrade to the latest
    stable version on their architecture:
    # emerge sync
    # emerge -pv ">=app-text/ghostscript-esp-7.05.6-r2"
    # emerge ">=app-text/ghostscript-esp-7.05.6-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2004-0967');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200410-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200410-18] Ghostscript: Insecure temporary file use in multiple scripts');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Ghostscript: Insecure temporary file use in multiple scripts');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-text/ghostscript-esp", unaffected: make_list("ge 7.07.1-r7", "rge 7.05.6-r2"), vulnerable: make_list("lt 7.07.1-r7")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
