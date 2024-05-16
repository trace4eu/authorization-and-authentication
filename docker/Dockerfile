# Dockerfile for trace4eu/authorization-and-authentication

FROM oryd/hydra:v1.11.8
MAINTAINER Markus Sabadello <markus@danubetech.com>

# install dependencies

USER root

RUN apk add sqlite

# build auth-uscis

ADD hydra.yml /opt/
ADD schema.sql /opt/
RUN sqlite3 /opt/db.sqlite </opt/schema.sql && \
    chown ory:ory /opt/db.sqlite && \
    chmod a+rw /opt/db.sqlite && \
    chmod a+rw /opt/ && \
    rm /opt/schema.sql
ADD docker/run.sh /opt/
RUN chmod a+x /opt/run.sh

# done

EXPOSE 4444
EXPOSE 4445
USER ory
ENTRYPOINT [""]
CMD ["/opt/run.sh"]
