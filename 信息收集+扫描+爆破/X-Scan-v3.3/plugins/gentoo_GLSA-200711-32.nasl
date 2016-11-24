# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-32.xml
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
 script_id(28321);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-32");
 script_cve_id("CVE-2007-5940");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-32 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-32
(Feynmf: Insecure temporary file creation)


    Kevin B. McCarty discovered that the feynmf.pl script creates a
    temporary "properly list" file at the location "$TMPDIR/feynmf$PID.pl",
    where $PID is the process ID.
  
Impact

    A local attacker could create symbolic links in the directory where the
    temporary files are written, pointing to a valid file somewhere on the
    filesystem that is writable by the user running Feynmf. When Feynmf
    writes the temporary file, the target valid file would then be
    overwritten with the contents of the Feynmf temporary file.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Feynmf users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-tex/feynmf-1.08-r2"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5940');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-32.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-32] Feynmf: Insecure temporary file creation');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Feynmf: Insecure temporary file creation');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-tex/feynmf", unaffected: make_list("ge 1.08-r2"), vulnerable: make_list("lt 1.08-r2")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
