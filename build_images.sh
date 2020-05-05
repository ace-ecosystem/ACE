#!/usr/bin/env bash
SAQ_HOME=${SAQ_HOME:.}

cd $SAQ_HOME || exit 1

if [ -d docker/mounts/mysql/init ]
then
    rm -rf docker/mounts/mysql/init
fi

mkdir -p docker/mounts/mysql/init

cat > docker/mounts/mysql/init/01-ace.sql<<EOF
CREATE DATABASE IF NOT EXISTS \`ace\`;
USE \`ace\`;
EOF

cat sql/ace_schema.sql >> docker/mounts/mysql/init/01-ace.sql

cat > docker/mounts/mysql/init/02-amc.sql<<EOF
CREATE DATABASE IF NOT EXISTS \`amc\`;
USE \`amc\`;
EOF

cat sql/amc_schema.sql >> docker/mounts/mysql/init/02-amc.sql

cat > docker/mounts/mysql/init/03-brocess.sql<<EOF
CREATE DATABASE IF NOT EXISTS \`brocess\`;
USE \`brocess\`;
EOF

cat sql/brocess_schema.sql >> docker/mounts/mysql/init/03-brocess.sql

cat > docker/mounts/mysql/init/04-email-archive.sql<<EOF
CREATE DATABASE IF NOT EXISTS \`email-archive\`;
USE \`email-archive\`;
EOF

cat sql/email-archive_schema.sql >> docker/mounts/mysql/init/04-email-archive.sql

cat > docker/mounts/mysql/init/05-vt-hash-cache.sql<<EOF
CREATE DATABASE IF NOT EXISTS \`vt-hash-cache\`;
USE \`vt-hash-cache\`;
EOF

cat sql/vt-hash-cache_schema.sql >> docker/mounts/mysql/init/05-vt-hash-cache.sql

cp docker/provision/mysql/init/99-users.sql docker/mounts/mysql/init

docker image build -f Dockerfile.ssl -t ace-ssl:latest .
docker image build -f Dockerfile.ace -t ace:latest .
docker image build -f Dockerfile.nginx -t ace-nginx:latest .
