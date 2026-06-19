Name: libneat
Version: 1.0.9
Release: 1
Summary: NEAT Project
License: BSD-3-Clause
Group: Applications/Internet
URL: https://github.com/NEAT-project/neat
Source: %{name}-%{version}.tar.xz

AutoReqProv: on
BuildRequires: cmake
BuildRequires: gcc
BuildRequires: gcc-c++
BuildRequires: (jansson-devel or libjansson-devel)
BuildRequires: ldns-devel
BuildRequires: libmnl-devel
BuildRequires: libuv-devel
BuildRequires: lksctp-tools-devel
BuildRequires: ((openssl-devel and openssl-devel-engine) or libopenssl-devel)
BuildRequires: pkgconf
BuildRequires: python3-devel
# BuildRequires: libusrsctp-devel

Requires: libneat1 = %{version}-%{release}
Requires: libneat-devel = %{version}-%{release}
Requires: libneat-examples = %{version}-%{release}
Requires: libneat-socketapi1 = %{version}-%{release}
Requires: libneat-socketapi-devel = %{version}-%{release}
Requires: libneat-socketapi-examples = %{version}-%{release}

%description
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.

%prep
%setup -q

%build
export CFLAGS="%{optflags} -ffat-lto-objects"
export CXXFLAGS="%{optflags} -ffat-lto-objects"
export LDFLAGS="%{build_ldflags}"
%cmake -DCMAKE_INSTALL_PREFIX=/usr -DSOCKET_API=1 -DUSRSCTP_SUPPORT=0 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1
%cmake_build

%install
%cmake_install

%files
%doc README.md


%package -n libneat1
Summary: Shared library for the NEAT Core API
Group:   System/Libraries

%description -n libneat1
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the shared library for the NEAT Core API.

%files -n libneat1
%{_libdir}/libneat.so.*

%post -n libneat1
ldconfig

%postun -n libneat1
ldconfig


%package -n libneat-devel
Summary: NEAT (Core API Development Files)
Group: Development/Libraries
Requires: libneat1 = %{version}-%{release}
Requires: libuv-devel

%description -n libneat-devel
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the development files for the NEAT Core API.

%files -n libneat-devel
%{_includedir}/neat.h
%{_libdir}/libneat-static.a
%{_libdir}/libneat.so


%package -n libneat-examples
Summary: NEAT (Core API Examples)
Group: Applications/Internet
Requires: libneat1 = %{version}-%{release}

%description -n libneat-examples
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Core API.

%files -n libneat-examples
%dir %attr(0755, root, root) %{_libdir}/libneat
%{_libdir}/libneat/client
%{_libdir}/libneat/client_data
%{_libdir}/libneat/client_http_get
%{_libdir}/libneat/client_http_run_once
%{_libdir}/libneat/msbench
%{_libdir}/libneat/peer
%{_libdir}/libneat/server_chargen
%{_libdir}/libneat/server_daytime
%{_libdir}/libneat/server_discard
%{_libdir}/libneat/server_echo
%{_libdir}/libneat/server_http
%{_libdir}/libneat/tneat
%{_libdir}/libneat/minimal_client
%{_libdir}/libneat/minimal_server
%{_libdir}/libneat/minimal_server2
%{_libdir}/libneat/client_dtls_echo
%{_libdir}/libneat/server_dtls_echo


%package -n libneat-socketapi1
Summary: NEAT (Socket API Library)
Group: Development/Libraries
Requires: libneat1 = %{version}-%{release}

%description -n libneat-socketapi1
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the library for the NEAT Sockets API.

%files -n libneat-socketapi1
%{_libdir}/libneat-socketapi.so.*

%post -n libneat-socketapi1
ldconfig

%postun -n libneat-socketapi1
ldconfig


%package -n libneat-socketapi-devel
Summary: NEAT (Socket API Development Files)
Group: Development/Libraries
Requires: libneat-devel = %{version}-%{release}
Requires: libneat-socketapi1 = %{version}-%{release}

%description -n libneat-socketapi-devel
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the development files for the NEAT Sockets API.

%files -n libneat-socketapi-devel
%{_includedir}/neat-socketapi.h
%{_libdir}/libneat-socketapi-static.a
%{_libdir}/libneat-socketapi.so


%package -n libneat-socketapi-examples
Summary: NEAT (Socket API Examples)
Group: Applications/Internet
Requires: libneat-socketapi1 = %{version}-%{release}

%description -n libneat-socketapi-examples
The NEAT project wants to achieve a complete redesign of the way in which
Internet applications interact with the network. The goal is to allow network
“services” offered to applications – such as reliability, low-delay
communication or security – to be dynamically tailored based on application
demands, current network conditions, hardware capabilities or local policies,
and also to support the integration of new network functionality in an
evolutionary fashion, without applications having to be rewritten. This
architectural change will make the Internet truly “enhanceable”, by allowing
applications to seamlessly and more easily take advantage of new network
features as they evolve.
This package contains the built examples for the NEAT Sockets API.

%files  -n libneat-socketapi-examples
%dir %attr(0755, root, root) %{_libdir}/libneat
%{_libdir}/libneat/httpget
%{_libdir}/libneat/httpserver1
%{_libdir}/libneat/httpserver2-select
%{_libdir}/libneat/httpserver2-threads


%changelog
* Wed Dec 10 2025 Thomas Dreibholz <dreibh@simula.no> - 1.0.9-1
- New upstream release.
* Fri Jul 11 2025 Thomas Dreibholz <dreibh@simula.no> - 1.0.8-1
- New upstream release.
* Sat Dec 14 2024 Thomas Dreibholz <dreibh@simula.no> - 1.0.7
- New upstream release.
* Sat Dec 14 2024 Thomas Dreibholz <dreibh@simula.no> - 1.0.6
- New upstream release.
* Wed Dec 06 2023 Thomas Dreibholz <dreibh@simula.no> - 1.0.5
- New upstream release.
* Wed Feb 08 2023 Thomas Dreibholz <dreibh@simula.no> - 1.0.4
- New upstream release.
* Thu Feb 17 2022 Thomas Dreibholz <dreibh@simula.no> - 1.0.3
- New upstream release.
* Wed Feb 16 2022 Thomas Dreibholz <dreibh@simula.no> - 1.0.2
- New upstream release.
* Thu Dec 05 2019 Thomas Dreibholz <dreibh@iem.uni-due.de> - 1.0.1
- New upstream release.
* Fri Aug 23 2019 Thomas Dreibholz <dreibh@iem.uni-due.de> - 1.0.0
- New upstream release.
* Fri Dec 02 2016 Thomas Dreibholz <dreibh@simula.no> 0.0.1
- Initial RPM release
