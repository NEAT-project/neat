# Created by: Thomas Dreibholz <dreibh@iem.uni-due.de>
# $FreeBSD$

PORTNAME=	libneat
PORTVERSION=	0.0.1~td200
CATEGORIES=	net
MASTER_SITES=	https://packages.nntb.no/software/libneat

MAINTAINER=	dreibh@iem.uni-due.de
COMMENT=	NEAT Project

LICENSE=	BSD
LICENSE_FILE=	${WRKSRC}/COPYING

USES=		cmake
USE_LDCONFIG=	yes

CMAKE_ARGS+=    -DSOCKET_API=1 -DUSRSCTP_SUPPORT=0 -DSCTP_MULTISTREAMING=1 -DFLOW_GROUPS=1

.include <bsd.port.mk>
