# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200803-23.xml
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
 script_id(31594);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200803-23");
 script_cve_id("CVE-2008-0665", "CVE-2008-0666");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200803-23 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200803-23
(Website META Language: Insecure temporary file usage)


    Temporary files are handled insecurely in the files
    wml_backend/p1_ipp/ipp.src, wml_contrib/wmg.cgi, and
    wml_backend/p3_eperl/eperl_sys.c, allowing users to overwrite or delete
    arbitrary files with the privileges of the user running the program.
  
Impact

    Local users can exploit the insecure temporary file vulnerabilities via
    symlink attacks to perform certain actions with escalated privileges.
  
Workaround

    Restrict access to the temporary directory to trusted users only.
  
');
script_set_attribute(attribute:'solution', value: '
    All Website META Language users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=dev-lang/wml-2.0.11-r3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0665');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0666');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200803-23.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200803-23] Website META Language: Insecure temporary file usage');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Website META Language: Insecure temporary file usage');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "dev-lang/wml", unaffected: make_list("ge 2.0.11-r3"), vulnerable: make_list("lt 2.0.11-r3")
)) { security_note(0); exit(0); }
exit(0, "Host is not affected");
