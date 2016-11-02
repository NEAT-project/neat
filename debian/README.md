Debian Packaging for libneat
============================

[![Jenkins](https://img.shields.io/jenkins/s/https/jenkins.erg.abdn.ac.uk/libneat-debs.svg)](https://jenkins.erg.abdn.ac.uk/job/libneat-debs/)

This folder contains the required files to build Debian source and binary
packages. The package is compliant with Debian Policy version 3.9.8, however it
is maintained here in 3.0 (native) source format and should be converted to 3.0
(quilt) if it were to be included in the Debian distribution. This is a task
for distribution packagers and the packaging files in this repository are
provided only for convenience.

The following binary packages are built:

 * libneat0 - Shared library
 * libneat-dev - Development files (i.e. /usr/lib symlinks and header files)
 * libneat-docs - Sphinx generated HTML documentation

*Note: The name of the shared library package will change based on the major
part of the soname version. This aids in library transitions within Debian.
Packages using libneat should Build-Depend on the libneat-dev package and
dh_makeshlibs will automatically add the correct versioned shared library
package during the build.*

Building the Packages
---------------------

The package targets Debian unstable and may not build for older or derivative
distributions. It is recommended to use git-buildpackage to build the Debian
package:

    sudo apt install git-buildpackage
    git clone https://github.com/NEAT-project/neat.git
    cd neat
    gbp buildpackage --git-pbuilder

The source package (i.e. .dsc, .orig.tar.gz and .debian.tar.gz) and the three
binary packages (i.e. .deb) will be found in the parent directory after the
build is complete.

The packages can be installed with:

    sudo dpkg -i libneat*.deb
    sudo apt -f install

This will install the packages using dpkg and then allow apt to finish
installing dependencies and configuring the packages.

Continuous Integration
----------------------

There is a jenkins job configured to poll the GitHub repository every 5 minutes
and attempt to build the Debian packages if there are changes. The status of
the build and build logs can be found at:

 * https://jenkins.erg.abdn.ac.uk/job/libneat-debs/

More Information
----------------

More information on Debian packaging can be found in the [Guide for Debian
Maintainers](https://www.debian.org/doc/manuals/debmake-doc/index.en.html).
