# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200612-15.xml
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
 script_id(23867);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200612-15");
 script_cve_id("CVE-2006-6474");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200612-15 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200612-15
(McAfee VirusScan: Insecure DT_RPATH)


    Jakub Moc of Gentoo Linux discovered that McAfee VirusScan was
    distributed with an insecure DT_RPATH which included the current
    working directory, rather than $ORIGIN which was probably intended.
  
Impact

    An attacker could entice a VirusScan user to scan an arbitrary file and
    execute arbitrary code with the privileges of the VirusScan user by
    tricking the dynamic loader into loading an untrusted ELF DSO. An
    automated system, such as a mail scanner, may be subverted to execute
    arbitrary code with the privileges of the process invoking VirusScan.
  
Workaround

    Do not scan files or execute VirusScan from an untrusted working
    directory.
  
');
script_set_attribute(attribute:'solution', value: '
    As VirusScan verifies that it has not been modified before executing,
    it is not possible to correct the DT_RPATH. Furthermore, this would
    violate the license that VirusScan is distributed under. For this
    reason, the package has been masked in Portage pending the resolution
    of this issue.
    # emerge --ask --verbose --unmerge "app-antivirus/vlnx"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-6474');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200612-15.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200612-15] McAfee VirusScan: Insecure DT_RPATH');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'McAfee VirusScan: Insecure DT_RPATH');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/vlnx", unaffected: make_list(), vulnerable: make_list("le 4510e")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
