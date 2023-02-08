# Created by: Thomas Dreibholz <thomas.dreibholz@gmail.com>
# $FreeBSD$

PORTNAME=	libneat
PORTVERSION=	1.0.4
CATEGORIES=	net
MASTER_SITES=	https://packages.nntb.no/software/libneat/

MAINTAINER=	thomas.dreibholz@gmail.com
COMMENT=	NEAT Project

LICENSE=	BSD
# LICENSE_FILE=	${WRKSRC}/COPYING

LIB_DEPENDS=    libjansson.so:devel/jansson \
		libldns.so:dns/ldns \
		libuv.so:devel/libuv
BUILD_DEPENDS=  swig:devel/swig

USES=		cmake ssl
USE_LDCONFIG=	yes

CMAKE_ARGS+=    -DSOCKET_API=1 -DUSRSCTP_SUPPORT=0 -DWEBRTC_SUPPORT=0 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1

PLIST_SUB=      VERSION=${PORTVERSION}

.include <bsd.port.mk>
