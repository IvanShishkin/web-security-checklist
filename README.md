# Чек-лист безопасности для веб-проекта

- [Настройка сервера](#настройка-сервера)
- [Базы данных](#базы-данных)
- [Кодовая база](#кодовая-база)
- [Аутентификация и авторизация](#аутентификация-и-авторизация)
- [Защита от атак](#защита-от-атак)
- [API безопасность](#api-безопасность)
- [CI/CD безопасность](#cicd-безопасность)
- [Мониторинг и реагирование](#мониторинг-и-реагирование)

## Настройка сервера

### SSH конфигурация

- **Подключение к серверу по SSH через ключи**
  - Использовать современные ключи ED25519 вместо RSA
  ```bash
  # Генерация ED25519 ключа
  ssh-keygen -t ed25519 -C "your_email@example.com"
  ```
  - Запретить аутентификацию по паролю полностью

- **Индивидуальные SSH ключи для каждого разработчика**
  - Каждый разработчик должен иметь собственный ключ
  - Хранить публичные ключи в `~/.ssh/authorized_keys`
  - Документировать владельцев ключей

- **Проводить плановые аудиты активных SSH ключей**
  - Ежеквартальная проверка актуальности ключей
  - Удаление ключей уволенных сотрудников
  - Проверка корректности настройки SSH конфигурации

- **Расширенная конфигурация SSH** (`/etc/ssh/sshd_config`)
  ```bash
  # Запретить root доступ
  PermitRootLogin no
  
  # Отключить аутентификацию по паролю
  PasswordAuthentication no
  PubkeyAuthentication yes
  ChallengeResponseAuthentication no
  
  # Использовать только протокол 2
  Protocol 2
  
  # Ограничить пользователей
  AllowUsers user1 user2
  
  # Сменить стандартный порт (опционально)
  Port 2222
  
  # Ограничить максимальное количество попыток
  MaxAuthTries 3
  MaxSessions 2
  
  # Таймауты
  ClientAliveInterval 300
  ClientAliveCountMax 2
  LoginGraceTime 60
  
  # Отключить пересылку X11
  X11Forwarding no
  
  # Применить изменения
  sudo systemctl reload sshd
  ```

- **Настройка Fail2ban для защиты от брутфорса**
  ```bash
  # Установка
  sudo apt install fail2ban
  
  # Создать локальную конфигурацию
  sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
  ```
  
  Базовая конфигурация `/etc/fail2ban/jail.local`:
  ```ini
  [DEFAULT]
  bantime = 3600
  findtime = 600
  maxretry = 5
  destemail = admin@example.com
  sendername = Fail2Ban
  action = %(action_mwl)s
  
  [sshd]
  enabled = true
  port = ssh,2222
  logpath = %(sshd_log)s
  maxretry = 3
  bantime = 86400
  
  [nginx-http-auth]
  enabled = true
  filter = nginx-http-auth
  port = http,https
  logpath = /var/log/nginx/error.log
  
  [nginx-limit-req]
  enabled = true
  filter = nginx-limit-req
  port = http,https
  logpath = /var/log/nginx/error.log
  ```
  - Настройка мониторинга логов Fail2ban: https://www.fail2ban.org/wiki/index.php/MANUAL_0_8

### Обновления и патчи

- **Своевременное обновление системы**
  ```bash
  # Настройка автоматических обновлений безопасности (Ubuntu/Debian)
  sudo apt install unattended-upgrades
  sudo dpkg-reconfigure -plow unattended-upgrades
  ```
  - Операционная система должна получать критические обновления безопасности
  - Службы и утилиты должны своевременно обновляться
  - Настроить уведомления о доступных обновлениях

### SSL/TLS конфигурация

- **Проверка корректности установки SSL сертификата**
  - Онлайн проверка: https://www.isplicense.ru/ssl-tools/checker/
  - Расширенная проверка: https://www.ssllabs.com/ssltest/
  - Проверка в терминале:
  ```bash
  # Установка sslscan
  sudo apt install sslscan
  
  # Проверка сертификата
  sslscan your-domain.com
  
  # Проверка через openssl
  openssl s_client -connect your-domain.com:443 -servername your-domain.com
  ```

- **Настройка современного TLS**
  
  Конфигурация для Nginx (`/etc/nginx/nginx.conf`):
  ```nginx
  # Использовать только TLS 1.2 и 1.3
  ssl_protocols TLSv1.2 TLSv1.3;
  
  # Современные cipher suites
  ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
  ssl_prefer_server_ciphers off;
  
  # OCSP Stapling
  ssl_stapling on;
  ssl_stapling_verify on;
  resolver 8.8.8.8 8.8.4.4 valid=300s;
  resolver_timeout 5s;
  
  # SSL session cache
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_session_tickets off;
  
  # DH параметры
  ssl_dhparam /etc/nginx/dhparam.pem;
  ```
  
  Генерация DH параметров:
  ```bash
  openssl dhparam -out /etc/nginx/dhparam.pem 4096
  ```

### Security Headers

- **Настройка заголовков CSP (Content Security Policy)**
  - Информация по настройке: https://habr.com/ru/companies/southbridge/articles/471746/
  
  Пример для Nginx:
  ```nginx
  add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
  ```
  - Использовать CSP Generator: https://report-uri.com/home/generate
  - Начинать с режима report-only для тестирования

- **Полный набор Security Headers**
  
  Конфигурация для Nginx:
  ```nginx
  # HSTS - принудительное использование HTTPS
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
  
  # Защита от XSS
  add_header X-XSS-Protection "1; mode=block" always;
  
  # Запрет на определение MIME-типа браузером
  add_header X-Content-Type-Options "nosniff" always;
  
  # Защита от clickjacking
  add_header X-Frame-Options "SAMEORIGIN" always;
  
  # Referrer Policy
  add_header Referrer-Policy "strict-origin-when-cross-origin" always;
  
  # Permissions Policy (замена Feature-Policy)
  add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=()" always;
  
  # Скрыть версию сервера
  server_tokens off;
  ```
  
  Для Apache (`.htaccess` или конфигурация):
  ```apache
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  Header always set X-XSS-Protection "1; mode=block"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  ServerTokens Prod
  ServerSignature Off
  ```

### Firewall и сетевая безопасность

- **Минимизация открытых портов**
  - Обычно открыты из вне: 80 (HTTP), 443 (HTTPS), 22 или custom (SSH)
  - Все остальные порты должны быть закрыты или доступны только из внутренней сети
  - Подробнее про эксплуатацию открытых портов: https://habr.com/ru/articles/446772/
  
  Проверка открытых портов:
  ```bash
  # Локально
  sudo netstat -tulpn
  sudo ss -tulpn
  
  # Извне
  nmap -p- your-server-ip
  ```

- **Настройка UFW (Uncomplicated Firewall)**
  ```bash
  # Установка
  sudo apt install ufw
  
  # Политика по умолчанию - запретить все входящие
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  
  # Разрешить SSH (перед включением!)
  sudo ufw allow 22/tcp
  # или для custom порта
  sudo ufw allow 2222/tcp
  
  # Разрешить HTTP/HTTPS
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  
  # Ограничить количество подключений к SSH (защита от брутфорса)
  sudo ufw limit 22/tcp
  
  # Разрешить доступ с конкретного IP
  sudo ufw allow from 192.168.1.100 to any port 22
  
  # Включить firewall
  sudo ufw enable
  
  # Проверить статус
  sudo ufw status verbose
  ```

- **Альтернатива: iptables**
  ```bash
  # Сбросить правила
  sudo iptables -F
  
  # Политика по умолчанию
  sudo iptables -P INPUT DROP
  sudo iptables -P FORWARD DROP
  sudo iptables -P OUTPUT ACCEPT
  
  # Разрешить loopback
  sudo iptables -A INPUT -i lo -j ACCEPT
  
  # Разрешить установленные соединения
  sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  
  # Разрешить SSH, HTTP, HTTPS
  sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  
  # Защита от сканирования портов
  sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
  sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
  
  # Защита от SYN flood
  sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
  
  # Сохранить правила
  sudo iptables-save > /etc/iptables/rules.v4
  ```

### HTTP to HTTPS редирект

- **Перенаправление HTTP на HTTPS**
  
  Nginx:
  ```nginx
  server {
      listen 80;
      server_name example.com www.example.com;
      return 301 https://$server_name$request_uri;
  }
  ```
  
  Apache:
  ```apache
  <VirtualHost *:80>
      ServerName example.com
      Redirect permanent / https://example.com/
  </VirtualHost>
  ```

### Мониторинг и логирование

- **Настройка мониторинга SSH подключений**
  - Информация настройки мониторинга через Zabbix: https://serveradmin.ru/monitoring-ssh-loginov-v-zabbix/
  - Альтернативные инструменты: Prometheus + Node Exporter, Grafana

- **Централизованное логирование**
  
  Настройка rsyslog для отправки логов:
  ```bash
  # /etc/rsyslog.d/50-default.conf
  *.* @@log-server.example.com:514
  ```
  
  Альтернативы:
  - ELK Stack (Elasticsearch, Logstash, Kibana)
  - Graylog
  - Loki + Grafana

- **Логирование критических событий**
  - Успешные и неуспешные попытки входа (SSH, веб-интерфейс)
  - Изменения в правах доступа к файлам
  - Изменения в конфигурации системы
  - Sudo команды
  
  Настройка auditd:
  ```bash
  sudo apt install auditd
  
  # Отслеживание изменений важных файлов
  sudo auditctl -w /etc/passwd -p wa -k passwd_changes
  sudo auditctl -w /etc/shadow -p wa -k shadow_changes
  sudo auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config_changes
  ```

### Права доступа к файлам

- **Разграничение прав доступа к файлам и директориям**
  - Владелец файлов проекта: `user:user`
  - Файлы должны иметь права 644 (`-rw-r--r--`)
  - Директории должны иметь права 755 (`drwxr-xr-x`)
  - Директории и файлы, которые веб-сервер может создавать/изменять, должны иметь владельца `www-data:user` с правами 664 для файлов и 775 для директорий
  
  Примеры команд:
  ```bash
  # Установить правильные права на весь проект
  sudo find /var/www/project -type f -exec chmod 644 {} \;
  sudo find /var/www/project -type d -exec chmod 755 {} \;
  
  # Для директорий загрузок/кеша
  sudo chown -R www-data:user /var/www/project/uploads
  sudo chmod -R 775 /var/www/project/uploads
  ```

### Hardening операционной системы

- **Настройка sysctl параметров безопасности**
  
  Создать или отредактировать `/etc/sysctl.d/99-security.conf`:
  ```bash
  # Защита от IP spoofing
  net.ipv4.conf.all.rp_filter = 1
  net.ipv4.conf.default.rp_filter = 1
  
  # Игнорировать ICMP redirects
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv6.conf.all.accept_redirects = 0
  net.ipv4.conf.all.send_redirects = 0
  
  # Игнорировать source routed packets
  net.ipv4.conf.all.accept_source_route = 0
  net.ipv6.conf.all.accept_source_route = 0
  
  # Защита от SYN flood
  net.ipv4.tcp_syncookies = 1
  net.ipv4.tcp_max_syn_backlog = 2048
  net.ipv4.tcp_synack_retries = 2
  net.ipv4.tcp_syn_retries = 5
  
  # Логирование подозрительных пакетов
  net.ipv4.conf.all.log_martians = 1
  
  # Отключить IPv6 (если не используется)
  net.ipv6.conf.all.disable_ipv6 = 1
  net.ipv6.conf.default.disable_ipv6 = 1
  
  # Применить настройки
  sudo sysctl -p /etc/sysctl.d/99-security.conf
  ```

- **SELinux/AppArmor базовая настройка**
  
  Для Ubuntu/Debian (AppArmor):
  ```bash
  # Проверить статус
  sudo aa-status
  
  # Включить профиль в режиме enforce
  sudo aa-enforce /etc/apparmor.d/usr.sbin.nginx
  
  # Или в режиме complain для тестирования
  sudo aa-complain /etc/apparmor.d/usr.sbin.nginx
  ```
  
  Для CentOS/RHEL (SELinux):
  ```bash
  # Проверить статус
  sestatus
  
  # Установить режим enforcing
  sudo setenforce 1
  
  # Сделать постоянным в /etc/selinux/config
  SELINUX=enforcing
  ```

### Rate Limiting на уровне веб-сервера

- **Защита от DDoS и брутфорса через Rate Limiting**
  
  Nginx (`/etc/nginx/nginx.conf`):
  ```nginx
  http {
      # Определение зон rate limiting
      limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
      limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
      limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
      
      # Ограничение количества соединений
      limit_conn_zone $binary_remote_addr zone=addr:10m;
      
      server {
          # Применение rate limiting
          location / {
              limit_req zone=general burst=20 nodelay;
              limit_conn addr 10;
          }
          
          location /login {
              limit_req zone=login burst=2;
          }
          
          location /api/ {
              limit_req zone=api burst=200 nodelay;
          }
      }
  }
  ```
  
  Apache (mod_ratelimit и mod_evasive):
  ```apache
  <IfModule mod_ratelimit.c>
      <Location />
          SetOutputFilter RATE_LIMIT
          SetEnv rate-limit 400
      </Location>
  </IfModule>
  
  <IfModule mod_evasive24.c>
      DOSHashTableSize 3097
      DOSPageCount 5
      DOSSiteCount 50
      DOSPageInterval 1
      DOSSiteInterval 1
      DOSBlockingPeriod 60
  </IfModule>
  ```

### Резервное копирование

- **Настройка системы резервного копирования**
  
  Базовый скрипт бэкапа:
  ```bash
  #!/bin/bash
  # /usr/local/bin/backup.sh
  
  BACKUP_DIR="/backup"
  DATE=$(date +%Y%m%d_%H%M%S)
  
  # Бэкап файлов проекта
  tar -czf $BACKUP_DIR/project_$DATE.tar.gz /var/www/project
  
  # Бэкап базы данных
  mysqldump -u user -ppassword database > $BACKUP_DIR/db_$DATE.sql
  gzip $BACKUP_DIR/db_$DATE.sql
  
  # Удалить бэкапы старше 30 дней
  find $BACKUP_DIR -type f -mtime +30 -delete
  
  # Отправить на удаленный сервер (опционально)
  rsync -avz $BACKUP_DIR/ user@backup-server:/backups/
  ```
  
  Настройка cron для автоматического бэкапа:
  ```bash
  # Ежедневный бэкап в 2 часа ночи
  0 2 * * * /usr/local/bin/backup.sh
  ```
  
  Рекомендации:
  - Хранить бэкапы на отдельном сервере или в облаке
  - Шифровать бэкапы перед отправкой
  - Регулярно проверять возможность восстановления из бэкапов
  - Использовать инкрементальные бэкапы для экономии места

### Веб-сервер PHP

- **Не использовать встроенный веб-сервер PHP на production**
  - Никогда не запускайте проект на встроенном веб-сервере PHP (`php -S`)
  - На production PHP должен работать как модуль Apache или в режиме PHP-FPM (FastCGI)
  - Встроенный сервер предназначен только для разработки и не имеет необходимых функций безопасности

---

## Базы данных

### Сетевая безопасность БД

- **Ограничение удалённого доступа к базам данных**
  - По умолчанию БД должна слушать только localhost (127.0.0.1)
  - Если требуется удалённый доступ, использовать firewall для ограничения IP адресов
  
  MySQL/MariaDB (`/etc/mysql/mysql.conf.d/mysqld.cnf`):
  ```ini
  # Слушать только localhost
  bind-address = 127.0.0.1
  
  # Или конкретный IP для удалённого доступа
  bind-address = 192.168.1.100
  ```
  
  PostgreSQL (`/etc/postgresql/*/main/postgresql.conf`):
  ```ini
  listen_addresses = 'localhost'
  ```

- **Закрытие портов БД через firewall**
  ```bash
  # UFW - запретить доступ к MySQL извне
  sudo ufw deny 3306/tcp
  
  # UFW - разрешить доступ только с конкретного IP
  sudo ufw allow from 192.168.1.100 to any port 3306
  
  # iptables - запретить внешний доступ к PostgreSQL
  sudo iptables -A INPUT -p tcp --dport 5432 -s 127.0.0.1 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 5432 -j DROP
  ```

### Начальная настройка безопасности

- **Установка пароля root и удаление тестовых пользователей**
  
  MySQL/MariaDB:
  ```bash
  # Запустить скрипт безопасной установки
  sudo mysql_secure_installation
  ```
  
  Скрипт выполнит:
  - Установку пароля для root
  - Удаление анонимных пользователей
  - Запрет удалённого входа для root
  - Удаление тестовой базы данных
  
  PostgreSQL:
  ```bash
  # Установить пароль для пользователя postgres
  sudo -u postgres psql
  ALTER USER postgres PASSWORD 'strong_password';
  ```

### Управление пользователями и привилегиями

- **Не использовать пользователя root для работы приложения**
  - Пользователь root имеет неограниченные привилегии
  - Приложение должно работать с ограниченным пользователем

- **Создание отдельных пользователей для каждой базы данных**
  
  MySQL:
  ```sql
  -- Создать пользователя
  CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'strong_password';
  
  -- Создать базу данных
  CREATE DATABASE app_database;
  
  -- Выдать минимально необходимые привилегии
  GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'appuser'@'localhost';
  
  -- Применить изменения
  FLUSH PRIVILEGES;
  ```
  
  PostgreSQL:
  ```sql
  -- Создать пользователя
  CREATE USER appuser WITH PASSWORD 'strong_password';
  
  -- Создать базу данных
  CREATE DATABASE app_database OWNER appuser;
  
  -- Выдать привилегии
  GRANT CONNECT ON DATABASE app_database TO appuser;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO appuser;
  ```

- **Ограничение привилегий пользователя БД**
  - Выдавать только необходимые привилегии (principle of least privilege)
  - Избегать привилегий: FILE, SUPER, PROCESS, GRANT OPTION
  - Подробнее про права пользователей MySQL: https://losst.pro/sozdanie-polzovatelya-mysql#2_%D0%9F%D1%80%D0%B0%D0%B2%D0%B0_%D0%BF%D0%BE%D0%BB%D1%8C%D0%B7%D0%BE%D0%B2%D0%B0%D1%82%D0%B5%D0%BB%D1%8F_MySQL
  
  Базовые привилегии для веб-приложения:
  ```sql
  -- Только основные операции с данными
  GRANT SELECT, INSERT, UPDATE, DELETE ON database.* TO 'user'@'localhost';
  
  -- Если нужны DDL операции (создание таблиц)
  GRANT CREATE, DROP, ALTER, INDEX ON database.* TO 'user'@'localhost';
  
  -- Проверка текущих привилегий
  SHOW GRANTS FOR 'user'@'localhost';
  ```

### Шифрование соединений

- **Настройка SSL/TLS для подключений к БД**
  
  MySQL - генерация сертификатов:
  ```bash
  # MySQL автоматически создаёт сертификаты при установке
  # Проверка наличия SSL
  mysql -u root -p -e "SHOW VARIABLES LIKE '%ssl%';"
  
  # Включить обязательное использование SSL
  # В /etc/mysql/mysql.conf.d/mysqld.cnf
  require_secure_transport = ON
  ```
  
  Настройка клиента MySQL:
  ```ini
  [client]
  ssl-ca=/var/lib/mysql/ca.pem
  ssl-cert=/var/lib/mysql/client-cert.pem
  ssl-key=/var/lib/mysql/client-key.pem
  ```
  
  PostgreSQL (`/etc/postgresql/*/main/postgresql.conf`):
  ```ini
  ssl = on
  ssl_cert_file = '/etc/ssl/certs/server.crt'
  ssl_key_file = '/etc/ssl/private/server.key'
  ssl_ca_file = '/etc/ssl/certs/ca.crt'
  ```
  
  В `pg_hba.conf` требовать SSL:
  ```
  hostssl all all 0.0.0.0/0 md5
  ```

### Шифрование данных

- **Шифрование данных at rest (на диске)**
  
  Варианты реализации:
  - Полное шифрование диска (LUKS для Linux)
  - Шифрование на уровне файловой системы
  - Встроенное шифрование БД
  
  MySQL - Transparent Data Encryption (TDE):
  ```sql
  -- Установить keyring plugin (MySQL 8.0+)
  INSTALL PLUGIN keyring_file SONAME 'keyring_file.so';
  
  -- Создать таблицу с шифрованием
  CREATE TABLE sensitive_data (
      id INT PRIMARY KEY,
      data VARCHAR(255)
  ) ENCRYPTION='Y';
  
  -- Зашифровать существующую таблицу
  ALTER TABLE existing_table ENCRYPTION='Y';
  ```
  
  PostgreSQL - использование pgcrypto:
  ```sql
  -- Установить расширение
  CREATE EXTENSION IF NOT EXISTS pgcrypto;
  
  -- Шифрование данных при вставке
  INSERT INTO users (email, password) 
  VALUES ('user@example.com', crypt('password', gen_salt('bf', 12)));
  
  -- Проверка пароля
  SELECT * FROM users 
  WHERE email = 'user@example.com' 
  AND password = crypt('input_password', password);
  ```

- **Шифрование чувствительных полей на уровне приложения**
  - Шифровать персональные данные перед сохранением в БД
  - Использовать проверенные библиотеки (OpenSSL, Sodium)
  - Хранить ключи шифрования отдельно от данных

### Логирование и мониторинг

- **Включить ведение журнала запросов**
  
  MySQL - General Query Log (не для production):
  ```sql
  SET GLOBAL general_log = 'ON';
  SET GLOBAL general_log_file = '/var/log/mysql/query.log';
  ```
  
  MySQL - Binary Log (для репликации и восстановления):
  ```ini
  # В /etc/mysql/mysql.conf.d/mysqld.cnf
  log_bin = /var/log/mysql/mysql-bin.log
  expire_logs_days = 7
  max_binlog_size = 100M
  ```

- **Включить Slow Query Log**
  
  MySQL:
  ```sql
  SET GLOBAL slow_query_log = 'ON';
  SET GLOBAL slow_query_log_file = '/var/log/mysql/slow-query.log';
  SET GLOBAL long_query_time = 2;  -- секунды
  SET GLOBAL log_queries_not_using_indexes = 'ON';
  ```
  
  PostgreSQL:
  ```ini
  # В postgresql.conf
  log_min_duration_statement = 2000  # миллисекунды
  log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
  log_checkpoints = on
  log_connections = on
  log_disconnections = on
  log_lock_waits = on
  ```

- **Мониторинг подозрительной активности**
  - Множественные неудачные попытки входа
  - Необычные паттерны запросов
  - Попытки SQL injection
  - Массовые операции DELETE/UPDATE без WHERE
  
  Настройка алертов в MySQL:
  ```sql
  -- Создать таригер для логирования критических операций
  CREATE TRIGGER audit_delete
  AFTER DELETE ON important_table
  FOR EACH ROW
  INSERT INTO audit_log (action, table_name, old_data, timestamp)
  VALUES ('DELETE', 'important_table', OLD.*, NOW());
  ```

### Резервное копирование

- **Регулярное резервное копирование баз данных**
  
  MySQL - полный дамп:
  ```bash
  #!/bin/bash
  # Скрипт бэкапа MySQL
  
  BACKUP_DIR="/backup/mysql"
  DATE=$(date +%Y%m%d_%H%M%S)
  MYSQL_USER="backup_user"
  MYSQL_PASS="backup_password"
  
  # Создать директорию
  mkdir -p $BACKUP_DIR
  
  # Бэкап всех баз данных
  mysqldump -u $MYSQL_USER -p$MYSQL_PASS --all-databases \
    --single-transaction --quick --lock-tables=false \
    > $BACKUP_DIR/all_databases_$DATE.sql
  
  # Или бэкап конкретной базы
  mysqldump -u $MYSQL_USER -p$MYSQL_PASS database_name \
    > $BACKUP_DIR/database_$DATE.sql
  
  # Сжать дамп
  gzip $BACKUP_DIR/database_$DATE.sql
  
  # Удалить старые бэкапы (старше 30 дней)
  find $BACKUP_DIR -type f -mtime +30 -delete
  ```
  
  PostgreSQL:
  ```bash
  #!/bin/bash
  BACKUP_DIR="/backup/postgresql"
  DATE=$(date +%Y%m%d_%H%M%S)
  
  # Полный бэкап
  sudo -u postgres pg_dumpall > $BACKUP_DIR/all_databases_$DATE.sql
  
  # Или конкретная база
  sudo -u postgres pg_dump database_name > $BACKUP_DIR/database_$DATE.sql
  
  # Сжать
  gzip $BACKUP_DIR/database_$DATE.sql
  ```

- **Стратегия резервного копирования**
  - Полные бэкапы: ежедневно или еженедельно
  - Инкрементальные бэкапы: несколько раз в день (через binary logs)
  - Хранить бэкапы на отдельном сервере или в облаке
  - Шифровать бэкапы перед передачей
  - Регулярно тестировать восстановление из бэкапов
  
  Автоматизация через cron:
  ```bash
  # Ежедневный бэкап в 3 часа ночи
  0 3 * * * /usr/local/bin/mysql_backup.sh
  
  # Еженедельный полный бэкап в воскресенье
  0 2 * * 0 /usr/local/bin/mysql_full_backup.sh
  ```

### Защита от SQL Injection

- **Использование подготовленных запросов (Prepared Statements)**
  
  Это главная защита от SQL injection. Обязательно к использованию!
  
  PHP MySQLi:
  ```php
  // ПРАВИЛЬНО - Prepared Statement
  $stmt = $mysqli->prepare("SELECT * FROM users WHERE email = ? AND status = ?");
  $stmt->bind_param("ss", $email, $status);
  $stmt->execute();
  $result = $stmt->get_result();
  
  // НЕПРАВИЛЬНО - конкатенация строк
  // $query = "SELECT * FROM users WHERE email = '" . $email . "'";
  ```
  
  Подробнее про Prepared Statements в MySQLi: https://www.php.net/manual/ru/mysqli.quickstart.prepared-statements.php
  
  PHP PDO:
  ```php
  // ПРАВИЛЬНО - Named parameters
  $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email AND status = :status");
  $stmt->execute(['email' => $email, 'status' => $status]);
  $result = $stmt->fetchAll();
  
  // ПРАВИЛЬНО - Positional parameters
  $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ? AND status = ?");
  $stmt->execute([$email, $status]);
  ```
  
  Подробнее про Prepared Statements в PDO: https://www.php.net/manual/ru/pdo.prepared-statements.php

- **Валидация и экранирование данных (дополнительный уровень)**
  - Всегда используйте Prepared Statements как основную защиту
  - Валидация входных данных на уровне приложения
  - Whitelist валидация вместо blacklist
  
  Примеры:
  ```php
  // Валидация типов данных
  $id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
  if ($id === false) {
      die('Invalid ID');
  }
  
  // Для динамических имён таблиц/колонок (где prepared statements не работают)
  $allowed_columns = ['name', 'email', 'created_at'];
  $column = in_array($_GET['sort'], $allowed_columns) ? $_GET['sort'] : 'id';
  ```

### Дополнительные меры безопасности

- **Удаление истории команд оболочки MySQL**
  ```bash
  # Очистить историю текущей сессии
  cat /dev/null > ~/.mysql_history
  
  # Отключить историю для всех последующих сессий
  ln -s /dev/null ~/.mysql_history
  ```

- **Ограничение размера запросов и результатов**
  
  MySQL:
  ```ini
  # В /etc/mysql/mysql.conf.d/mysqld.cnf
  max_allowed_packet = 16M
  max_connections = 150
  max_user_connections = 50
  ```
  
  PostgreSQL:
  ```ini
  max_connections = 100
  shared_buffers = 256MB
  ```

- **Отключение опасных функций**
  
  MySQL:
  ```sql
  -- Отключить LOAD DATA INFILE для всех
  SET GLOBAL local_infile = 0;
  
  -- Запретить использование символических ссылок
  -- В my.cnf
  skip-symbolic-links
  ```

- **Регулярное обновление СУБД**
  - Следить за обновлениями безопасности
  - Применять патчи своевременно
  - Подписаться на security mailing lists
  - MySQL: https://www.mysql.com/support/security.html
  - PostgreSQL: https://www.postgresql.org/support/security/

---

## Кодовая база

### Безопасная структура проекта

- **Разделение публичной и приватной частей проекта**
  - Вынести публичные скрипты (index.php, assets) в отдельную директорию
  - Установить эту директорию как DOCUMENT_ROOT веб-сервера
  - Все остальные файлы (конфигурация, библиотеки) должны быть выше DOCUMENT_ROOT
  
  Пример структуры:
  ```
  /var/www/myproject/
  ├── app/              # Логика приложения (вне DOCUMENT_ROOT)
  ├── config/           # Конфигурация (вне DOCUMENT_ROOT)
  ├── vendor/           # Composer зависимости (вне DOCUMENT_ROOT)
  ├── .env              # Переменные окружения (вне DOCUMENT_ROOT)
  ├── .git/             # Git репозиторий (вне DOCUMENT_ROOT)
  └── public/           # DOCUMENT_ROOT - только это доступно по HTTP
      ├── index.php
      ├── css/
      ├── js/
      └── images/
  ```

- **Защита конфиденциальных файлов и директорий**
  
  Файлы и директории, которые должны быть недоступны по HTTP:
  - `.git`, `.gitignore`
  - `.env`, `config.php`
  - `composer.json`, `composer.lock`, `vendor/`
  - `package.json`, `node_modules/`
  - `logs/`, `storage/`
  - README.md, документация
  
  Nginx конфигурация:
  ```nginx
  # Запретить доступ к .git
  location ~ /\.git {
      return 404;
  }
  
  # Запретить доступ к .env файлам
  location ~ /\.env {
      return 404;
  }
  
  # Запретить доступ к composer файлам
  location ~ /composer\.(json|lock) {
      return 404;
  }
  
  # Запретить доступ к vendor
  location ~ /vendor {
      return 404;
  }
  
  # Запретить доступ к node_modules
  location ~ /node_modules {
      return 404;
  }
  ```
  
  Apache (.htaccess):
  ```apache
  # Запретить доступ к .git
  RedirectMatch 404 /\.git
  
  # Запретить доступ к конфигурационным файлам
  <FilesMatch "^\.env|composer\.(json|lock)|package\.json">
      Require all denied
  </FilesMatch>
  
  # Запретить доступ к директориям
  RedirectMatch 404 /vendor/
  RedirectMatch 404 /node_modules/
  ```

- **Удаление технических и тестовых файлов**
  - Не оставлять в production: `phpinfo.php`, `test.php`, `debug.php`
  - Удалять временные файлы разработки
  - Не загружать `.bak`, `.old`, `.tmp` файлы на сервер

### Управление конфиденциальными данными

- **Использование переменных окружения для хранения секретов**
  
  Не хранить в коде:
  - Пароли баз данных
  - API ключи и токены
  - Секретные ключи шифрования
  - SMTP учётные данные
  
  Использовать `.env` файл:
  ```env
  DB_HOST=localhost
  DB_NAME=myapp
  DB_USER=appuser
  DB_PASSWORD=secure_password_here
  
  API_KEY=your_api_key_here
  APP_SECRET=random_secret_key
  
  MAIL_HOST=smtp.example.com
  MAIL_USERNAME=user@example.com
  MAIL_PASSWORD=mail_password
  ```
  
  PHP - загрузка через библиотеку (например, vlucas/phpdotenv):
  ```php
  require_once __DIR__ . '/../vendor/autoload.php';
  
  $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
  $dotenv->load();
  
  $dbHost = $_ENV['DB_HOST'];
  $dbPassword = $_ENV['DB_PASSWORD'];
  ```

- **Добавить .env в .gitignore**
  ```
  .env
  .env.local
  .env.production
  ```

### Валидация и санитизация входных данных

- **Всегда валидировать пользовательские данные**
  
  PHP функции для валидации и санитизации:
  - `filter_var()` - валидация и фильтрация
  - `htmlspecialchars()` - экранирование HTML
  - `strip_tags()` - удаление HTML тегов
  - `trim()` - удаление пробелов
  - `htmlentities()` - конвертация в HTML entities
  
  Примеры:
  ```php
  // Валидация email
  $email = filter_var($_POST['email'], FILTER_VALIDATE_EMAIL);
  if ($email === false) {
      die('Invalid email');
  }
  
  // Валидация URL
  $url = filter_var($_POST['url'], FILTER_VALIDATE_URL);
  
  // Валидация целого числа
  $id = filter_var($_POST['id'], FILTER_VALIDATE_INT);
  
  // Санитизация строки (удаление тегов)
  $name = strip_tags($_POST['name']);
  $name = trim($name);
  
  // Экранирование для вывода в HTML
  echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
  ```

- **Whitelist валидация вместо blacklist**
  ```php
  // ПРАВИЛЬНО - разрешённые значения
  $allowed_sorts = ['name', 'date', 'price'];
  $sort = in_array($_GET['sort'], $allowed_sorts) ? $_GET['sort'] : 'date';
  
  // НЕПРАВИЛЬНО - блокировка опасных значений
  // if (!preg_match('/[;<>]/', $_GET['sort'])) { ... }
  ```

- **Валидация типов и диапазонов данных**
  ```php
  // Проверка длины строки
  if (strlen($username) < 3 || strlen($username) > 20) {
      die('Username must be 3-20 characters');
  }
  
  // Проверка формата (регулярные выражения)
  if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
      die('Username can only contain letters, numbers and underscore');
  }
  
  // Проверка числового диапазона
  if ($age < 18 || $age > 120) {
      die('Invalid age');
  }
  ```

### Защита от опасных функций

- **Никогда не использовать пользовательские данные с опасными функциями**
  
  Опасные функции PHP:
  - `eval()` - выполнение PHP кода
  - `exec()`, `shell_exec()`, `system()`, `passthru()` - выполнение системных команд
  - `unserialize()` - десериализация (может привести к RCE)
  - `include()`, `require()` - с динамическими путями
  
  ```php
  // НИКОГДА так не делать
  // eval($_GET['code']);
  // exec($_POST['command']);
  // include($_GET['page'] . '.php');
  // unserialize($_COOKIE['data']);
  
  // Если необходимо выполнить команду - использовать escapeshellarg()
  $filename = escapeshellarg($_POST['filename']);
  $output = shell_exec("cat $filename");
  
  // Для include использовать whitelist
  $allowed_pages = ['home', 'about', 'contact'];
  $page = in_array($_GET['page'], $allowed_pages) ? $_GET['page'] : 'home';
  include $page . '.php';
  ```

### Безопасная работа с файлами

- **Валидация загружаемых файлов**
  
  Проверять:
  - Расширение файла
  - MIME-тип
  - Размер файла
  - Содержимое (magic bytes)
  
  ```php
  // Проверка через pathinfo
  $filename = $_FILES['upload']['name'];
  $extension = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
  
  $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
  if (!in_array($extension, $allowed_extensions)) {
      die('File type not allowed');
  }
  
  // Проверка через SplFileInfo
  $file = new SplFileInfo($filename);
  $extension = strtolower($file->getExtension());
  
  // Проверка MIME-типа
  $finfo = finfo_open(FILEINFO_MIME_TYPE);
  $mime = finfo_file($finfo, $_FILES['upload']['tmp_name']);
  finfo_close($finfo);
  
  $allowed_mimes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
  if (!in_array($mime, $allowed_mimes)) {
      die('Invalid file type');
  }
  
  // Проверка размера (5MB максимум)
  if ($_FILES['upload']['size'] > 5 * 1024 * 1024) {
      die('File too large');
  }
  ```

- **Переименование загруженных файлов**
  ```php
  // Генерация безопасного имени файла
  $extension = strtolower(pathinfo($_FILES['upload']['name'], PATHINFO_EXTENSION));
  $new_filename = bin2hex(random_bytes(16)) . '.' . $extension;
  
  // Или с использованием uniqid
  $new_filename = uniqid('upload_', true) . '.' . $extension;
  
  // Перемещение файла
  $upload_dir = '/var/www/uploads/';
  move_uploaded_file($_FILES['upload']['tmp_name'], $upload_dir . $new_filename);
  ```

- **Ограничение доступа к директории загрузок**
  - Загруженные файлы не должны выполняться как скрипты
  - Добавить `.htaccess` в директорию загрузок
  
  Apache (.htaccess в /uploads):
  ```apache
  # Запретить выполнение PHP
  php_flag engine off
  
  # Или через handler
  RemoveHandler .php .phtml .php3 .php4 .php5 .phps
  RemoveType .php .phtml .php3 .php4 .php5 .phps
  
  # Разрешить только просмотр
  Options -Indexes -ExecCGI
  ```
  
  Nginx:
  ```nginx
  location /uploads {
      # Запретить выполнение PHP
      location ~ \.php$ {
          return 403;
      }
  }
  ```

### Использование подготовленных запросов

- **Prepared Statements для всех SQL запросов**
  
  Уже подробно описано в разделе "Базы данных", но повторим ключевые моменты:
  
  MySQLi:
  - Подробнее: https://www.php.net/manual/ru/mysqli.quickstart.prepared-statements.php
  
  PDO:
  - Подробнее: https://www.php.net/manual/ru/pdo.prepared-statements.php
  
  ```php
  // Всегда использовать Prepared Statements
  $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
  $stmt->execute([$email]);
  
  // Никогда не конкатенировать SQL с пользовательскими данными
  // НЕПРАВИЛЬНО: $sql = "SELECT * FROM users WHERE email = '$email'";
  ```

### Аудит зависимостей проекта

- **Проверка подлинности пакетов**
  - Убедиться что пакет от реального вендора, а не форк злоумышленника
  - Проверить количество загрузок и репутацию
  - Проверить дату последнего обновления
  - Проверить наличие security policy

- **Осторожность с малопопулярными библиотеками**
  - Если устанавливаете непопулярную библиотеку - проверьте её код
  - Посмотреть количество issues и pull requests
  - Проверить наличие maintainer

- **Сканирование уязвимостей в зависимостях**
  
  Frontend (npm):
  ```bash
  # Проверка уязвимостей
  npm audit
  
  # Автоматическое исправление
  npm audit fix
  
  # Принудительное исправление (может сломать совместимость)
  npm audit fix --force
  ```
  
  PHP (Composer):
  - Использовать: https://github.com/FriendsOfPHP/security-advisories#checking-for-vulnerabilities
  - Или: https://github.com/Roave/SecurityAdvisories
  
  Установка Security Advisories:
  ```bash
  composer require --dev roave/security-advisories:dev-latest
  ```
  
  Проверка через Local PHP Security Checker:
  ```bash
  # Установка
  curl -L https://github.com/fabpot/local-php-security-checker/releases/download/v2.0.6/local-php-security-checker_linux_amd64 -o local-php-security-checker
  chmod +x local-php-security-checker
  
  # Проверка
  ./local-php-security-checker
  ```

- **Автоматизация проверки в CI/CD**
  
  Пример для GitHub Actions:
  ```yaml
  - name: Security audit (npm)
    run: npm audit --audit-level=high
  
  - name: Security audit (composer)
    run: composer audit
  ```
  
  Пример для GitLab CI:
  ```yaml
  security:audit:
    script:
      - npm audit
      - composer audit
    allow_failure: false
  ```

### Административная панель

- **Изменение стандартных URL административных панелей**
  - Не использовать: `/admin`, `/administrator`, `/wp-admin`, `/bitrix/admin`
  - Использовать уникальный, сложный URL: `/secure-panel-a8f9d2c1`

- **Ограничение доступа по IP адресам**
  
  Nginx:
  ```nginx
  location /admin {
      allow 192.168.1.100;  # Офисный IP
      allow 10.0.0.0/8;     # Внутренняя сеть
      deny all;
      
      # Остальная конфигурация
  }
  ```
  
  Apache (.htaccess):
  ```apache
  <Location /admin>
      Require ip 192.168.1.100
      Require ip 10.0.0.0/8
  </Location>
  ```

- **Дополнительная HTTP Basic авторизация**
  
  Nginx:
  ```nginx
  location /admin {
      auth_basic "Restricted Area";
      auth_basic_user_file /etc/nginx/.htpasswd;
  }
  ```
  
  Создание .htpasswd:
  ```bash
  # Установка утилиты
  sudo apt install apache2-utils
  
  # Создание пользователя
  sudo htpasswd -c /etc/nginx/.htpasswd admin_user
  
  # Добавление ещё одного пользователя
  sudo htpasswd /etc/nginx/.htpasswd another_user
  ```
  
  Apache (.htaccess):
  ```apache
  AuthType Basic
  AuthName "Restricted Area"
  AuthUserFile /var/www/.htpasswd
  Require valid-user
  ```

### Настройка PHP для безопасности

- **Hardening php.ini**
  
  Рекомендуемые настройки (`/etc/php/8.x/fpm/php.ini`):
  ```ini
  # Отключить вывод ошибок на production
  display_errors = Off
  display_startup_errors = Off
  log_errors = On
  error_log = /var/log/php/error.log
  
  # Отключить опасные функции
  disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,phpinfo
  
  # Ограничить директории для include/require
  open_basedir = /var/www/project:/tmp
  
  # Запретить загрузку удалённых файлов
  allow_url_fopen = Off
  allow_url_include = Off
  
  # Ограничения на загрузку файлов
  file_uploads = On
  upload_max_filesize = 10M
  max_file_uploads = 5
  
  # Ограничения памяти и времени выполнения
  memory_limit = 128M
  max_execution_time = 30
  max_input_time = 60
  
  # Скрыть версию PHP
  expose_php = Off
  
  # Ограничения на POST данные
  post_max_size = 20M
  max_input_vars = 1000
  
  # Session security
  session.cookie_httponly = 1
  session.cookie_secure = 1
  session.cookie_samesite = Strict
  session.use_strict_mode = 1
  session.use_only_cookies = 1
  session.name = PHPSESSID_CUSTOM
  ```

---

## Аутентификация и авторизация

### Безопасное хранение паролей

- **Использование современных алгоритмов хеширования**
  
  Рекомендуемые алгоритмы:
  - **Argon2** (Argon2i, Argon2id) - наиболее безопасный на сегодня, победитель Password Hashing Competition 2015
  - **bcrypt** - проверенный временем, хороший выбор для большинства проектов
  - **scrypt** - хорошая альтернатива, устойчив к аппаратным атакам
  
  Не использовать:
  - MD5, SHA1, SHA256 без соли и итераций - слишком быстрые для перебора
  - Простое хеширование без соли - уязвимо к rainbow table атакам
  
  Ключевые принципы:
  - Использовать встроенные функции языка для хеширования паролей
  - Соль должна генерироваться автоматически и быть уникальной для каждого пароля
  - Настраивать cost factor (вычислительную сложность) в зависимости от мощности сервера
  - При изменении параметров хеширования - обновлять старые хеши при следующем входе пользователя
  - Проверять пароль через специальную функцию verify, а не сравнением строк

- **Никогда не хранить пароли в открытом виде**
  - Даже во временных таблицах
  - Даже в логах

### Политики паролей

- **Требования к паролям**
  - Минимальная длина: 12-16 символов (чем длиннее, тем лучше)
  - Рекомендовать комбинацию: буквы разного регистра, цифры, спецсимволы
  - Проверять по словарю часто используемых паролей (top 10000-100000)
  - Запрещать использование личной информации (имя, email, дата рождения)
  - Не требовать обязательную периодическую смену пароля без причины
  - Разрешать использование пробелов и emoji в паролях
  
  Проверки на стороне сервера:
  - Минимальная и максимальная длина
  - Наличие различных типов символов
  - Отсутствие в списке скомпрометированных паролей
  - Отсутствие повторяющихся символов или простых последовательностей
  - Различие с предыдущими паролями пользователя

- **Принудительная смена скомпрометированных паролей**
  - Проверять пароли через Have I Been Pwned API
  - Требовать смену при обнаружении утечки

### Многофакторная аутентификация (MFA/2FA)

- **Внедрение двухфакторной аутентификации**
  
  Типы 2FA (по убыванию безопасности):
  - **Hardware tokens** (YubiKey, Titan Key) - наиболее безопасно, защита от фишинга
  - **TOTP** (Time-based One-Time Password) - приложения Google Authenticator, Authy, Microsoft Authenticator
  - **Push-уведомления** - подтверждение через мобильное приложение
  - **Email коды** - отправка кода на почту
  - **SMS коды** - наименее безопасно, уязвимо к SIM-swapping атакам
  
  Рекомендации по внедрению:
  - Предложить несколько методов 2FA на выбор
  - Сделать 2FA обязательным для администраторов и привилегированных пользователей
  - Генерировать QR-код для удобной настройки TOTP
  - Показывать секретный ключ текстом для ручного ввода
  - Сохранять секрет в зашифрованном виде в базе данных
  - Использовать окно допуска (±1 интервал) для компенсации рассинхронизации времени
  - Предотвращать повторное использование одного кода

- **Backup codes для восстановления доступа**
  
  Рекомендации:
  - Генерировать 8-10 одноразовых кодов при включении 2FA
  - Длина кода: 8-10 символов (буквы и цифры)
  - Хранить в базе данных в виде хешей (как пароли)
  - Каждый код можно использовать только один раз
  - После использования кода - удалить его из базы
  - Предупреждать пользователя о количестве оставшихся кодов
  - Позволять регенерировать новые коды (старые при этом инвалидируются)
  - Показывать коды только один раз при генерации
  - Рекомендовать пользователю сохранить коды в безопасном месте

### Session Management

- **Безопасная конфигурация сессий**
  
  Критичные настройки для cookie сессий:
  - `HttpOnly` - запрет доступа к cookie через JavaScript (защита от XSS)
  - `Secure` - передача cookie только по HTTPS
  - `SameSite=Strict` или `Lax` - защита от CSRF атак
  - Использовать криптографически стойкий генератор ID сессий
  - Отключить возможность передачи session ID через URL
  - Установить разумное время жизни cookie
  
  Дополнительные меры:
  - Использовать уникальное имя для session cookie (не стандартное PHPSESSID)
  - Хранить сессии на сервере (не в cookie)
  - Шифровать данные сессии если они содержат чувствительную информацию
  - Использовать защищённое хранилище для сессий (Redis с аутентификацией, зашифрованные файлы)

- **Регенерация Session ID**
  
  Когда необходимо регенерировать ID сессии:
  - Сразу после успешного входа в систему
  - При повышении уровня привилегий (например, переход в админ-панель)
  - Периодически во время длительной активной сессии (каждые 15-30 минут)
  - При выполнении критичных операций
  
  Принципы:
  - Старый session ID должен быть немедленно инвалидирован
  - Данные сессии сохраняются и переносятся на новый ID
  - Регенерация должна быть прозрачной для пользователя
  - Избегать Race Conditions при регенерации (использовать блокировки)

- **Таймаут сессии**
  
  Типы таймаутов:
  - **Idle timeout** (таймаут неактивности) - время с последнего действия пользователя
    - Рекомендуемое значение: 15-30 минут для обычных пользователей
    - 5-10 минут для административных панелей
  - **Absolute timeout** (абсолютный таймаут) - максимальное время жизни сессии
    - Рекомендуемое значение: 8-12 часов
  
  Реализация:
  - Сохранять время последней активности в сессии
  - Сохранять время начала сессии
  - При каждом запросе проверять оба таймаута
  - При истечении таймаута - уничтожить сессию и перенаправить на страницу входа
  - Предупреждать пользователя за 2-3 минуты до истечения (через JavaScript)
  - Обновлять время последней активности при каждом действии

- **Привязка сессии к характеристикам клиента**
  
  Что можно использовать для привязки:
  - **IP адрес** - привязка к IP клиента
    - Плюсы: простота, дополнительная безопасность
    - Минусы: проблемы с мобильными сетями, NAT, прокси
    - Рекомендация: использовать только для высоко защищённых приложений
  - **User-Agent** - строка идентификации браузера
    - Плюсы: стабильная в рамках одной сессии
    - Минусы: легко подделывается, может меняться при обновлении браузера
  - **Fingerprinting** - уникальный отпечаток браузера
    - Комбинация: разрешение экрана, часовой пояс, язык, установленные шрифты
  
  Реализация:
  - Сохранять характеристики при создании сессии
  - Проверять при каждом запросе
  - При несовпадении - уничтожить сессию и требовать повторной аутентификации
  - Логировать подозрительную активность
  - Уведомлять пользователя о попытке несанкционированного доступа

### JWT (JSON Web Tokens)

- **Безопасное использование JWT**
  
  Рекомендации по структуре и конфигурации:
  - Использовать надёжные, проверенные библиотеки для работы с JWT
  - **Обязательно** использовать алгоритм с подписью (HS256, RS256), никогда не использовать "none"
  - Для HS256 использовать секретный ключ длиной минимум 256 бит
  - Для RS256 использовать приватный ключ RSA 2048+ бит
  - Устанавливать короткое время жизни Access Token (15-30 минут)
  - Включать в payload только необходимые данные (не храните чувствительную информацию)
  
  Обязательные claims в payload:
  - `iss` (issuer) - идентификатор выдавшего токен
  - `aud` (audience) - для кого предназначен токен
  - `exp` (expiration) - время истечения токена
  - `iat` (issued at) - время выдачи
  - `jti` (JWT ID) - уникальный идентификатор токена
  
  Безопасность:
  - Хранить секретный ключ в переменных окружения, не в коде
  - Ротировать ключи подписи периодически
  - Валидировать все claims при проверке токена
  - Проверять алгоритм подписи (защита от атаки алгоритма)
  - Не доверять данным из payload без проверки подписи

- **Хранение JWT на клиенте**
  
  Варианты хранения (по убыванию безопасности):
  - **HttpOnly Cookies** - наиболее безопасный вариант
    - Защищено от XSS атак
    - Требует защиты от CSRF (используйте SameSite cookie или CSRF токены)
    - Автоматически отправляется с каждым запросом
  - **Memory (JavaScript переменные)** - для SPA
    - Токен хранится только в памяти, теряется при обновлении страницы
    - Защищено от XSS в закрытых вкладках
    - Требует Refresh Token в HttpOnly cookie
  - **SessionStorage** - приемлемый вариант для SPA
    - Очищается при закрытии вкладки
    - Уязвимо для XSS
  - **LocalStorage** - НЕ рекомендуется
    - Уязвимо для XSS атак
    - Токены остаются даже после закрытия браузера
    - Используйте только если нет альтернатив

- **Refresh Token механизм**
  
  Принципы работы:
  - Access Token - короткоживущий (15-30 мин), используется для API запросов
  - Refresh Token - долгоживущий (7-30 дней), используется только для получения нового Access Token
  
  Реализация Refresh Token:
  - Генерировать криптографически стойкий случайный токен (32+ байта)
  - Хранить хеш Refresh Token в БД с привязкой к пользователю
  - Хранить на клиенте в HttpOnly Secure cookie
  - Включить дополнительные поля: device info, IP, created_at, expires_at, last_used
  - Ограничить количество активных Refresh Token на пользователя (5-10)
  
  Безопасность Refresh Token:
  - Отзывать Refresh Token при выходе из системы
  - Использовать Refresh Token Rotation - при использовании старый токен инвалидируется и выдаётся новый
  - Детектировать повторное использование отозванного токена (возможная кража) и блокировать все токены пользователя
  - Позволять пользователю просматривать активные сессии и отзывать их
  - Автоматически отзывать токены при смене пароля или критичных настройках безопасности

### OAuth 2.0 / OpenID Connect

- **Использование проверенных библиотек**
  - Не пытайтесь реализовать OAuth 2.0 самостоятельно - спецификация сложная и легко допустить ошибки
  - Используйте проверенные библиотеки для вашего языка программирования
  - Проверяйте, что библиотека активно поддерживается и обновляется

- **Безопасная конфигурация OAuth**
  
  Обязательные меры безопасности:
  - **HTTPS обязательно** - для всех redirect_uri и API endpoints
  - **Whitelist redirect_uri** - точное совпадение, без wildcards и поддоменов
  - **State parameter** - криптографически случайное значение для защиты от CSRF
    - Генерировать уникальный state для каждого запроса
    - Сохранять в сессии и проверять в callback
    - Использовать только один раз и затем инвалидировать
  - **PKCE** (Proof Key for Code Exchange) - обязательно для публичных клиентов (мобильные, SPA)
    - Генерировать code_verifier случайным образом
    - Вычислять code_challenge = BASE64URL(SHA256(code_verifier))
    - Отправлять challenge при авторизации, verifier при обмене кода на токен
  - **Client Secret** - хранить в безопасности, никогда не экспонировать в клиентском коде
  - **Scope ограничения** - запрашивать минимально необходимые разрешения
  
  Проверки в callback:
  - Валидировать state parameter
  - Проверять что redirect_uri совпадает с зарегистрированным
  - Проверять error коды от провайдера
  - Валидировать ID token если используется OpenID Connect
  - Проверять nonce в ID token
  
  Хранение токенов:
  - Access Token - краткосрочное хранение в памяти или HttpOnly cookie
  - Refresh Token - HttpOnly, Secure cookie или зашифрованное хранилище
  - Никогда не храните токены в localStorage
  - Не логируйте токены

### Контроль доступа и авторизация

- **Role-Based Access Control (RBAC)**
  
  Основные концепции:
  - **Роли** - набор разрешений (admin, editor, user, guest)
  - **Разрешения** - конкретные действия (users.create, posts.edit, reports.view)
  - **Пользователи** - назначаются одна или несколько ролей
  
  Принципы реализации:
  - Использовать иерархию ролей (наследование разрешений)
  - Хранить роли и разрешения в базе данных для гибкости
  - Кешировать разрешения пользователя для производительности
  - Проверять права доступа на каждом уровне: маршрутизация, контроллеры, представления, API
  - Применять принцип least privilege - минимальные необходимые права
  
  Структура БД:
  - Таблица `roles`: id, name, description
  - Таблица `permissions`: id, name, description
  - Таблица `role_permissions`: role_id, permission_id
  - Таблица `user_roles`: user_id, role_id
  
  Проверка прав:
  - Загружать разрешения пользователя при аутентификации
  - Проверять перед выполнением действия
  - Возвращать 403 Forbidden при отсутствии прав
  - Логировать попытки несанкционированного доступа

- **Attribute-Based Access Control (ABAC)**
  - Более гибкая система контроля доступа на основе атрибутов
  - Учитывает контекст: время, местоположение, IP адрес, устройство
  - Проверка на основе: атрибутов пользователя, атрибутов ресурса, условий окружения
  - Позволяет создавать сложные политики доступа

- **Проверка авторизации на каждый запрос**
  
  Уровни защиты:
  - **Маршрутизация** - проверка прав на уровне URL
  - **Middleware** - промежуточный слой проверки перед контроллером
  - **Контроллер** - дополнительная проверка в методах
  - **Модель** - ограничение доступа к данным
  - **Представление** - скрытие элементов интерфейса
  
  Принципы:
  - Проверять аутентификацию перед авторизацией
  - Не полагаться только на скрытие элементов UI
  - Всегда проверять на backend, даже если frontend уже проверил
  - Возвращать корректные HTTP коды: 401 (не аутентифицирован), 403 (нет прав)
  - Не раскрывать детали почему доступ запрещён
  - Логировать все попытки несанкционированного доступа

### Защита от перебора паролей

- **Rate Limiting для формы входа**
  
  Стратегии ограничения:
  - **По IP адресу** - ограничение количества попыток с одного IP
    - Недостаток: проблемы с NAT, можно обойти через прокси
  - **По username/email** - ограничение попыток для конкретной учётной записи
    - Защищает от целевых атак на конкретный аккаунт
  - **Комбинированный подход** - ограничение по обоим параметрам
  
  Параметры:
  - Максимальное количество попыток: 3-5 в течение периода
  - Окно времени: 5-15 минут
  - Время блокировки: 15-30 минут (увеличивать экспоненциально при повторных нарушениях)
  - Использовать sliding window или fixed window алгоритм
  
  Реализация:
  - Хранить счётчики в быстром хранилище (Redis, Memcached)
  - Инкрементировать счётчик при неудачной попытке
  - Сбрасывать счётчик при успешном входе
  - Уведомлять пользователя о количестве оставшихся попыток
  - Логировать все заблокированные попытки
  
  Дополнительные меры:
  - Увеличивать задержку ответа с каждой неудачной попыткой (exponential backoff)
  - Требовать CAPTCHA после N неудачных попыток
  - Отправлять email уведомление владельцу аккаунта о множественных неудачных попытках
  - Временно блокировать учётную запись при превышении лимита

- **CAPTCHA для защиты от ботов**
  
  Типы CAPTCHA:
  - **reCAPTCHA v3** (Google) - невидимая, на основе поведенческого анализа
    - Выдаёт score от 0.0 до 1.0
    - Не требует взаимодействия пользователя
    - Рекомендуется для большинства случаев
  - **reCAPTCHA v2** - классический "I'm not a robot" checkbox или image challenge
  - **hCaptcha** - альтернатива от Cloudflare, более privacy-friendly
  - **Собственная CAPTCHA** - простые математические задачи или текстовая капча
  
  Когда использовать:
  - После 2-3 неудачных попыток входа
  - На странице регистрации
  - При сбросе пароля
  - На формах обратной связи
  - На формах комментариев
  
  Реализация:
  - Интегрировать на клиенте (JavaScript)
  - Обязательно валидировать токен на сервере
  - Не доверять только клиентской проверке
  - Хранить secret key в переменных окружения
  - Устанавливать минимальный score для reCAPTCHA v3 (обычно 0.5)
  - Обрабатывать ошибки валидации gracefully
  - Предоставлять fallback для пользователей без JavaScript

### Восстановление пароля

- **Безопасный процесс сброса пароля**
  
  Правильный flow:
  
  **Шаг 1: Запрос сброса пароля**
  - Принять email от пользователя
  - Генерировать криптографически стойкий токен (32+ байта случайных данных)
  - Хешировать токен перед сохранением в БД (как пароль)
  - Сохранить в таблице password_resets: user_id, token_hash, expires_at (обычно 1-2 часа), created_at
  - Отправить email с ссылкой содержащей оригинальный токен
  - Показать одинаковое сообщение независимо от существования email
  
  **Шаг 2: Переход по ссылке**
  - Извлечь токен из URL
  - Проверить что токен существует в БД (сравнивая хеши)
  - Проверить что токен не истёк
  - Если токен валиден - показать форму установки нового пароля
  - Если токен невалиден или истёк - показать сообщение об ошибке
  
  **Шаг 3: Установка нового пароля**
  - Валидировать новый пароль по политике безопасности
  - Проверить что новый пароль отличается от старого
  - Обновить пароль в БД
  - Немедленно удалить использованный токен
  - Инвалидировать все активные сессии пользователя
  - Отозвать все Refresh Tokens
  - Отправить email подтверждение об успешной смене пароля
  - Предложить включить 2FA если не включена
  
  Дополнительные меры:
  - Ограничить количество активных токенов сброса для одного пользователя (1-2)
  - Rate limiting на запросы сброса пароля (не более 3-5 в час)
  - Логировать все запросы и использования токенов сброса
  - Периодически очищать истёкшие токены из БД

- **Не раскрывать существование email**
  
  Принцип:
  - Показывать одинаковое сообщение независимо от того, существует ли пользователь с таким email
  - Это предотвращает перечисление (enumeration) пользователей
  - Защищает конфиденциальность пользователей
  
  Правильное сообщение:
  "If an account with this email exists, a password reset link has been sent"
  
  Неправильные сообщения:
  - "User not found" - раскрывает несуществующий email
  - "Email sent to user@example.com" - подтверждает существование аккаунта
  - Разная задержка ответа для существующих и несуществующих аккаунтов
  
  Дополнительно:
  - Задержка ответа должна быть одинаковой в обоих случаях
  - Всегда выполнять одинаковое количество операций (например, проверку БД)
  - Не возвращать разные HTTP статусы

---

## Защита от атак

### CSRF (Cross-Site Request Forgery)

- **Понимание угрозы CSRF**
  - Злоумышленник заставляет браузер жертвы отправить запрос на ваш сайт
  - Браузер автоматически отправляет cookies, включая session cookie
  - Сервер не может отличить легитимный запрос от поддельного
  - Жертва должна быть аутентифицирована на целевом сайте
  - Атака работает только для запросов изменяющих состояние (POST, PUT, DELETE)

- **CSRF токены (Synchronizer Token Pattern)**
  
  Принцип работы:
  - Генерировать уникальный криптографически стойкий токен для каждой сессии или формы
  - Включать токен в скрытое поле формы
  - Сохранять токен в сессии пользователя на сервере
  - При отправке формы проверять что токен из запроса совпадает с токеном в сессии
  - После использования можно регенерировать токен (one-time token) или использовать повторно (per-session token)
  
  Рекомендации:
  - Генерировать токены длиной минимум 128 бит случайных данных
  - Токены должны быть непредсказуемыми
  - Проверять токен для всех state-changing запросов (POST, PUT, DELETE, PATCH)
  - Токены должны быть привязаны к сессии пользователя
  - Устанавливать разумное время жизни токенов
  - Не передавать токены в URL (только в теле запроса или заголовках)

- **Double Submit Cookie Pattern**
  
  Альтернативный подход для stateless приложений:
  - Сгенерировать случайный токен
  - Установить токен в cookie (не HttpOnly!)
  - Требовать отправку того же токена в custom header или в теле запроса
  - Сравнить значения на сервере
  - Злоумышленник не может прочитать cookie из другого домена и не сможет отправить правильный токен

- **SameSite Cookie атрибут**
  
  Современная защита на уровне браузера:
  - `SameSite=Strict` - cookie отправляется только при запросах с того же сайта (максимальная защита)
  - `SameSite=Lax` - cookie отправляется при top-level navigation (GET запросы), но не при cross-site POST
  - `SameSite=None; Secure` - cookie отправляется всегда (требует HTTPS)
  
  Рекомендации:
  - Использовать `SameSite=Lax` как минимум для session cookies
  - Для критичных операций использовать `SameSite=Strict`
  - Всегда комбинировать с CSRF токенами для полной защиты

- **Дополнительные меры защиты от CSRF**
  - Проверять Origin и Referer заголовки (дополнительная защита)
  - Требовать повторную аутентификацию для критичных операций
  - Использовать CAPTCHA для особо важных действий
  - Избегать GET запросов для операций изменения данных
  - Логировать подозрительные запросы без валидного токена

### XSS (Cross-Site Scripting)

- **Типы XSS атак**
  
  **Reflected XSS (Отражённый)**
  - Вредоносный скрипт приходит в запросе (URL параметр, форма)
  - Сервер отражает его обратно без валидации
  - Скрипт выполняется в браузере жертвы
  - Требует социальной инженерии (жертва должна перейти по ссылке)
  
  **Stored XSS (Хранимый)**
  - Вредоносный скрипт сохраняется на сервере (комментарий, профиль)
  - Скрипт выполняется у всех кто просматривает эти данные
  - Наиболее опасный тип XSS
  - Не требует взаимодействия с жертвой
  
  **DOM-based XSS**
  - Уязвимость в клиентском JavaScript коде
  - Данные из URL или других источников попадают в DOM без санитизации
  - Выполняется полностью на клиенте, сервер может не участвовать

- **Защита от XSS через экранирование вывода**
  
  Контекстное экранирование - ключевой принцип:
  - **HTML контекст** - экранировать `<`, `>`, `&`, `"`, `'`
  - **HTML атрибуты** - экранировать кавычки и специальные символы
  - **JavaScript контекст** - использовать JSON encoding или JavaScript escaping
  - **CSS контекст** - избегать пользовательских данных в CSS, использовать CSS encoding
  - **URL контекст** - использовать URL encoding (percent encoding)
  
  Правила экранирования:
  - Экранировать всегда при выводе данных, не при вводе
  - Использовать функции фреймворка/шаблонизатора для экранирования
  - Никогда не доверять пользовательским данным
  - Экранировать даже данные из базы данных
  - Использовать правильное экранирование для каждого контекста

- **Content Security Policy (CSP)**
  
  Мощный механизм защиты от XSS на уровне браузера:
  - Определяет откуда можно загружать ресурсы (скрипты, стили, изображения)
  - Блокирует inline скрипты и eval() по умолчанию
  - Требует whitelist доменов для внешних ресурсов
  
  Базовая политика:
  - `default-src 'self'` - загрузка только с текущего домена
  - `script-src 'self'` - скрипты только с текущего домена
  - `style-src 'self' 'unsafe-inline'` - стили с домена + inline (если необходимо)
  - `img-src 'self' data: https:` - изображения с домена, data URLs и HTTPS
  - `font-src 'self'` - шрифты только с домена
  - `connect-src 'self'` - AJAX запросы только на свой домен
  - `frame-ancestors 'none'` - запретить использование в iframe
  - `base-uri 'self'` - ограничить base tag
  - `form-action 'self'` - формы отправляются только на свой домен
  
  Режимы CSP:
  - **Enforcement mode** - блокирует нарушения политики
  - **Report-only mode** - только логирует нарушения, не блокирует (для тестирования)
  
  Рекомендации:
  - Начинать с report-only режима
  - Избегать 'unsafe-inline' и 'unsafe-eval'
  - Использовать nonces или hashes для необходимых inline скриптов
  - Регулярно анализировать отчёты о нарушениях
  - Постепенно ужесточать политику

- **HttpOnly и Secure флаги для cookies**
  - `HttpOnly` - запрещает доступ к cookie через JavaScript (document.cookie)
  - `Secure` - cookie передаётся только по HTTPS
  - Защищает session cookies от кражи через XSS
  - Обязательно использовать для всех authentication cookies

- **Валидация и санитизация входных данных**
  - Whitelist валидация предпочтительнее blacklist
  - Ограничивать длину, формат, допустимые символы
  - Удалять или экранировать HTML теги если не требуется rich text
  - Для rich text использовать специализированные библиотеки санитизации (DOMPurify, HTML Purifier)
  - Никогда не полагаться только на клиентскую валидацию

- **Дополнительные меры**
  - Использовать современные фреймворки с встроенной защитой от XSS
  - Избегать innerHTML, используйте textContent или innerText
  - Не использовать eval() и Function() constructor
  - Не вставлять пользовательские данные в теги `<script>`, `<style>`, обработчики событий
  - Использовать автоматические сканеры для поиска XSS уязвимостей

### SQL Injection

- **Понимание угрозы SQL Injection**
  - Внедрение вредоносного SQL кода через пользовательский ввод
  - Может привести к: утечке данных, изменению/удалению данных, обход аутентификации, выполнение команд ОС
  - Возникает при конкатенации SQL запросов с пользовательскими данными
  - Одна из самых опасных и распространённых уязвимостей

- **Prepared Statements (Параметризованные запросы)**
  
  Главная и наиболее эффективная защита:
  - SQL код и данные разделены на уровне протокола
  - Данные никогда не интерпретируются как SQL код
  - Параметры передаются отдельно от запроса
  - СУБД сама экранирует специальные символы
  - Работает для всех СУБД (MySQL, PostgreSQL, SQLite, MS SQL)
  
  Обязательно использовать для:
  - Всех запросов с пользовательскими данными
  - WHERE условий
  - INSERT значений
  - UPDATE значений
  - LIMIT/OFFSET параметров
  
  Prepared statements НЕ работают для:
  - Динамических имён таблиц
  - Динамических имён колонок
  - Динамических ORDER BY
  - Для этих случаев использовать whitelist валидацию

- **ORM (Object-Relational Mapping)**
  - Использовать ORM фреймворки (Eloquent, Doctrine, Hibernate)
  - ORM автоматически использует prepared statements
  - Снижает риск SQL injection при правильном использовании
  - Внимание: raw queries в ORM всё ещё уязвимы

- **Принцип наименьших привилегий**
  - Пользователь БД приложения должен иметь минимальные права
  - Только SELECT, INSERT, UPDATE, DELETE на необходимые таблицы
  - Никаких административных привилегий (DROP, CREATE, GRANT)
  - Отдельные пользователи для разных компонентов приложения

- **Дополнительные меры защиты**
  - Валидация типов данных на уровне приложения
  - Использовать whitelist для имён таблиц/колонок
  - Экранирование как последнее средство (не полагайтесь только на него)
  - Web Application Firewall (WAF) для обнаружения попыток injection
  - Регулярное сканирование кода на SQL injection уязвимости
  - Логирование и мониторинг подозрительных SQL запросов
  - Отключить подробные сообщения об ошибках SQL на production

### XXE (XML External Entity)

- **Понимание угрозы XXE**
  - Атака на приложения обрабатывающие XML
  - Злоумышленник определяет внешние entity в XML документе
  - Может привести к: чтению локальных файлов, SSRF, DoS, выполнению кода
  - Возникает при небезопасной конфигурации XML парсера

- **Защита от XXE**
  
  Отключение внешних entities:
  - Отключить обработку внешних entities в XML парсере
  - Отключить DTD (Document Type Definition) обработку
  - Использовать безопасные конфигурации по умолчанию
  - Разные парсеры требуют разных настроек
  
  Рекомендации:
  - Обновлять XML библиотеки до последних версий
  - Использовать менее сложные форматы данных (JSON) где возможно
  - Валидировать XML против схемы (XSD)
  - Не позволять пользователям загружать произвольные XML/XSLT
  - Использовать whitelist для допустимых DTD/схем

- **Альтернативные форматы**
  - Предпочитать JSON вместо XML где возможно
  - JSON не поддерживает external entities
  - Проще и безопаснее в обработке

### SSRF (Server-Side Request Forgery)

- **Понимание угрозы SSRF**
  - Злоумышленник заставляет сервер делать HTTP запросы от своего имени
  - Может использоваться для: сканирования внутренней сети, доступа к метаданным облака, обхода firewall, атак на внутренние сервисы
  - Сервер может иметь доступ к ресурсам недоступным извне
  - Особенно опасно в облачных средах (AWS, GCP, Azure metadata)

- **Защита от SSRF**
  
  Валидация URL:
  - Использовать whitelist разрешённых доменов/IP
  - Блокировать частные IP диапазоны (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Блокировать localhost (127.0.0.0/8, ::1)
  - Блокировать link-local адреса (169.254.0.0/16)
  - Блокировать cloud metadata endpoints (169.254.169.254)
  - Проверять после DNS резолвинга (защита от DNS rebinding)
  
  Ограничения протоколов:
  - Разрешать только HTTP/HTTPS
  - Блокировать file://, gopher://, dict://, ftp:// и другие
  - Валидировать схему URL
  
  Сетевая изоляция:
  - Запросы делать из отдельной сети/подсети
  - Использовать отдельный egress proxy
  - Ограничить исходящий трафик на firewall
  
  Дополнительные меры:
  - Отключить редиректы или ограничить их количество
  - Ограничить время выполнения запроса (timeout)
  - Ограничить размер ответа
  - Не возвращать содержимое ответа пользователю без санитизации

### Path Traversal (Directory Traversal)

- **Понимание угрозы**
  - Доступ к файлам вне предназначенной директории
  - Использование последовательностей `../` для подъёма по дереву каталогов
  - Может привести к чтению конфиденциальных файлов (/etc/passwd, .env, исходный код)
  - Иногда возможна перезапись файлов

- **Защита от Path Traversal**
  
  Валидация пути:
  - Использовать whitelist разрешённых файлов
  - Проверять что canonical path находится внутри разрешённой директории
  - Удалять или блокировать последовательности `../`, `..\\`
  - Проверять абсолютный путь после резолвинга символических ссылок
  - Не полагаться только на замену `../` (можно обойти через `....//`)
  
  Безопасная работа с путями:
  - Использовать функции работы с путями языка (path.join, realpath)
  - Нормализовать пути перед проверкой
  - Хранить файлы вне document root
  - Использовать случайные имена файлов вместо оригинальных
  - Не принимать полные пути от пользователя, только идентификаторы
  
  Права доступа:
  - Ограничить права веб-сервера на файловую систему
  - Использовать chroot окружения где возможно
  - Разделение директорий для чтения и записи

### Command Injection (OS Command Injection)

- **Понимание угрозы**
  - Выполнение произвольных команд операционной системы
  - Возникает при передаче пользовательских данных в system(), exec(), shell_exec()
  - Может привести к полному компрометированию сервера
  - Использование метасимволов shell: `;`, `|`, `&`, `$()`, `` ` ``, `>`, `<`

- **Защита от Command Injection**
  
  Избегание выполнения команд:
  - Не использовать функции выполнения команд если возможно
  - Использовать API/библиотеки вместо внешних команд
  - Например: использовать встроенные функции работы с изображениями вместо ImageMagick
  
  Если команды необходимы:
  - Использовать функции с массивом аргументов (не строки для shell)
  - Экранировать аргументы специальными функциями (escapeshellarg, escapeshellcmd)
  - Whitelist валидация всех параметров
  - Жёстко закодировать команду, параметризовать только необходимое
  - Запускать команды с минимальными привилегиями
  - Использовать timeout для команд
  
  Дополнительные меры:
  - Использовать контейнеры/песочницы для изоляции
  - Отключить опасные функции в конфигурации языка
  - Логировать все выполняемые команды
  - Мониторить необычную активность процессов

### Insecure Deserialization

- **Понимание угрозы**
  - Десериализация непроверенных данных может привести к выполнению кода
  - Злоумышленник создаёт вредоносный сериализованный объект
  - При десериализации могут вызваться magic methods или конструкторы
  - Может привести к RCE (Remote Code Execution)

- **Защита от Insecure Deserialization**
  
  Избегание десериализации:
  - Не десериализовать данные от ненадёжных источников
  - Использовать JSON вместо нативной сериализации где возможно
  - JSON более безопасен т.к. не восстанавливает объекты с методами
  
  Если десериализация необходима:
  - Проверять HMAC подпись перед десериализацией
  - Whitelist разрешённых классов для десериализации
  - Использовать изолированное окружение для десериализации
  - Ограничивать типы десериализуемых объектов
  
  Дополнительные меры:
  - Логировать все операции десериализации
  - Мониторить аномальную активность
  - Регулярно обновлять библиотеки сериализации
  - Использовать статический анализ кода

### Clickjacking

- **Понимание угрозы**
  - Злоумышленник обманывает пользователя кликнуть на невидимый iframe
  - Пользователь думает что взаимодействует с легитимным сайтом
  - На самом деле клики перехватываются наложенным iframe
  - Может привести к: несанкционированным действиям, краже данных, изменению настроек

- **Защита от Clickjacking**
  
  **X-Frame-Options заголовок:**
  - `DENY` - полностью запрещает отображение в iframe
  - `SAMEORIGIN` - разрешает только с того же домена
  - `ALLOW-FROM uri` - разрешает с конкретного домена (устарело, не поддерживается везде)
  
  **Content-Security-Policy frame-ancestors:**
  - Современная замена X-Frame-Options
  - `frame-ancestors 'none'` - эквивалент DENY
  - `frame-ancestors 'self'` - эквивалент SAMEORIGIN
  - `frame-ancestors 'self' trusted.com` - whitelist доменов
  - Более гибкий и мощный механизм
  
  Рекомендации:
  - Использовать оба заголовка для совместимости
  - Для большинства сайтов использовать 'none' или 'self'
  - Тестировать легитимное использование iframe перед применением

- **Frame Busting**
  - JavaScript код для выхода из iframe (legacy подход)
  - Не надёжен, может быть обойдён
  - Использовать только как дополнительную защиту, не основную

### Open Redirect

- **Понимание угрозы**
  - Сайт перенаправляет пользователя на URL из параметра запроса
  - Злоумышленник создаёт ссылку на доверенный домен которая редиректит на вредоносный
  - Используется для фишинга (пользователь видит доверенный домен в адресной строке)
  - Может обойти whitelist в OAuth и других протоколах

- **Защита от Open Redirect**
  
  Валидация redirect URL:
  - Использовать whitelist разрешённых доменов для редиректа
  - Проверять что URL начинается с разрешённого домена
  - Избегать редиректов на произвольные внешние URL
  - Валидировать схему (только http/https)
  
  Безопасные подходы:
  - Использовать относительные URL для редиректов
  - Использовать ID/ключ вместо полного URL (mapping на сервере)
  - Показывать промежуточную страницу с предупреждением при внешнем редиректе
  - Требовать подтверждение для редиректа на внешние домены
  
  Дополнительные меры:
  - Логировать все редиректы на внешние домены
  - Не использовать редиректы для критичных операций
  - Избегать параметров типа `?redirect=`, `?return=`, `?next=`

---

## API безопасность

### Общие принципы безопасности API

- **HTTPS обязательно**
  - Все API endpoints должны работать только по HTTPS
  - Редиректить HTTP запросы на HTTPS
  - Использовать HSTS заголовок для принудительного HTTPS
  - Никогда не передавать чувствительные данные по HTTP

- **Аутентификация и авторизация**
  - Каждый endpoint должен проверять права доступа
  - Не полагаться на security through obscurity
  - Проверять авторизацию на сервере, не на клиенте
  - Различать аутентификацию (кто ты?) и авторизацию (что тебе можно?)

- **Валидация всех входных данных**
  - Валидировать тип, формат, длину, диапазон всех параметров
  - Использовать строгую типизацию где возможно
  - Отклонять неожиданные поля в запросах
  - Не доверять заголовкам от клиента

### REST API Best Practices

- **Правильное использование HTTP методов**
  - `GET` - только для чтения, должен быть idempotent и safe
  - `POST` - создание ресурсов, не idempotent
  - `PUT` - полное обновление, idempotent
  - `PATCH` - частичное обновление, может быть idempotent
  - `DELETE` - удаление, idempotent
  - Никогда не изменять данные через GET запросы

- **Правильные HTTP статус коды**
  - `200 OK` - успешный запрос
  - `201 Created` - ресурс создан
  - `204 No Content` - успешно, нет тела ответа
  - `400 Bad Request` - ошибка в запросе клиента
  - `401 Unauthorized` - требуется аутентификация
  - `403 Forbidden` - аутентифицирован, но нет прав
  - `404 Not Found` - ресурс не найден
  - `429 Too Many Requests` - превышен rate limit
  - `500 Internal Server Error` - ошибка сервера
  - `503 Service Unavailable` - сервис временно недоступен

- **Версионирование API**
  - Использовать версионирование с первого дня
  - Варианты: URL path (/v1/users), заголовок (Accept: application/vnd.api+json;version=1), query parameter
  - Поддерживать старые версии определённое время
  - Уведомлять о deprecated версиях
  - Не ломать обратную совместимость без предупреждения

- **Пагинация и ограничение результатов**
  - Всегда использовать пагинацию для списков
  - Установить максимальный размер страницы (100-1000 элементов)
  - Предоставлять метаданные: total, page, per_page, links
  - Использовать cursor-based pagination для больших наборов
  - Не возвращать весь набор данных по умолчанию

- **Фильтрация и сортировка**
  - Whitelist разрешённых полей для фильтрации
  - Whitelist разрешённых полей для сортировки
  - Валидировать операторы сравнения
  - Защищаться от SQL injection через фильтры

### API аутентификация

- **API ключи (API Keys)**
  
  Использование:
  - Для идентификации приложения/клиента
  - Не для аутентификации конечных пользователей
  - Подходит для server-to-server коммуникации
  
  Рекомендации:
  - Генерировать криптографически стойкие ключи (минимум 32 байта)
  - Хранить хеши ключей в базе данных, не plain text
  - Передавать в заголовке (X-API-Key или Authorization), не в URL
  - Поддерживать несколько ключей на клиента
  - Реализовать механизм отзыва ключей
  - Логировать использование каждого ключа
  - Устанавливать срок действия ключей
  - Позволять ротацию ключей без простоя

- **Bearer Tokens (JWT)**
  
  Преимущества:
  - Stateless - не требует хранения сессий
  - Содержит claims о пользователе
  - Может использоваться между микросервисами
  
  Безопасность:
  - Короткое время жизни (15-30 минут)
  - Использовать Refresh Token механизм
  - Проверять подпись токена
  - Проверять exp, iss, aud claims
  - Не хранить чувствительные данные в payload
  - Передавать в Authorization: Bearer заголовке
  - Иметь механизм отзыва токенов (blacklist или short TTL)

- **OAuth 2.0**
  
  Сценарии использования:
  - Делегированный доступ к API
  - Third-party приложения
  - Различные типы клиентов (web, mobile, SPA)
  
  Grant types:
  - Authorization Code - для web приложений (наиболее безопасный)
  - Authorization Code + PKCE - для SPA и mobile
  - Client Credentials - для server-to-server
  - Избегать Implicit flow и Resource Owner Password

- **mTLS (Mutual TLS)**
  - Клиент и сервер аутентифицируют друг друга через сертификаты
  - Наиболее безопасный метод для критичных API
  - Сложнее в настройке и поддержке
  - Подходит для межсервисной коммуникации

### Rate Limiting для API

- **Зачем нужен Rate Limiting**
  - Защита от DDoS атак
  - Предотвращение перебора (brute force)
  - Справедливое распределение ресурсов
  - Защита от неправильно работающих клиентов
  - Монетизация API (тарифные планы)

- **Стратегии Rate Limiting**
  
  **Fixed Window**
  - Фиксированные временные окна (например, 1000 запросов в час)
  - Простая реализация
  - Недостаток: burst в начале/конце окна
  
  **Sliding Window**
  - Скользящее окно времени
  - Более справедливое распределение
  - Сложнее в реализации
  
  **Token Bucket**
  - Bucket наполняется токенами с постоянной скоростью
  - Позволяет короткие всплески активности
  - Используется в AWS, многих CDN
  
  **Leaky Bucket**
  - Запросы обрабатываются с постоянной скоростью
  - Сглаживает всплески трафика
  - Может добавлять задержку

- **Уровни применения Rate Limiting**
  - По IP адресу - защита от анонимных атак
  - По API ключу - контроль использования приложением
  - По пользователю - индивидуальные лимиты
  - По endpoint - разные лимиты для разных операций
  - Глобальные лимиты - защита инфраструктуры

- **Информирование клиентов о лимитах**
  
  Заголовки ответа:
  - `X-RateLimit-Limit` - максимум запросов в окне
  - `X-RateLimit-Remaining` - оставшееся количество
  - `X-RateLimit-Reset` - время сброса счётчика (Unix timestamp)
  - `Retry-After` - через сколько секунд можно повторить (при 429)
  
  При превышении:
  - Возвращать 429 Too Many Requests
  - Включать Retry-After заголовок
  - Предоставлять понятное сообщение об ошибке
  - Не банить навсегда, использовать временные блокировки

### CORS (Cross-Origin Resource Sharing)

- **Понимание CORS**
  - Браузерный механизм безопасности
  - Ограничивает cross-origin HTTP запросы из JavaScript
  - Same-origin policy по умолчанию блокирует запросы
  - CORS позволяет серверу разрешить определённые cross-origin запросы

- **Безопасная настройка CORS**
  
  Что НЕ делать:
  - `Access-Control-Allow-Origin: *` с credentials - небезопасно и не работает
  - Автоматически отражать Origin заголовок в ответе - уязвимость
  - Разрешать все методы и заголовки без ограничений
  
  Правильная конфигурация:
  - Использовать whitelist разрешённых origins
  - Проверять Origin заголовок на сервере
  - Возвращать конкретный origin, не wildcard (если нужны credentials)
  - Ограничить разрешённые методы (Access-Control-Allow-Methods)
  - Ограничить разрешённые заголовки (Access-Control-Allow-Headers)
  - Установить разумное время кеширования preflight (Access-Control-Max-Age)
  
  Access-Control-Allow-Credentials:
  - Использовать true только если действительно нужны cookies
  - Требует указания конкретного origin (не *)
  - Тщательно проверять origin при включении

- **Preflight запросы**
  - Браузер отправляет OPTIONS запрос перед основным
  - Проверяет разрешён ли метод и заголовки
  - Сервер должен правильно отвечать на OPTIONS
  - Кешируется на время указанное в Access-Control-Max-Age

### Input Validation для API

- **Валидация на уровне схемы**
  - Использовать JSON Schema для валидации структуры
  - OpenAPI/Swagger спецификации с валидацией
  - Автоматически генерировать валидаторы из схемы
  - Отклонять запросы не соответствующие схеме

- **Типизация и ограничения**
  - Строгая проверка типов (string, number, boolean, array, object)
  - Минимальная и максимальная длина строк
  - Диапазоны для чисел (minimum, maximum)
  - Паттерны для строк (regex)
  - Enum для ограниченного набора значений
  - Максимальная глубина вложенности объектов
  - Максимальный размер массивов

- **Специфичная валидация**
  - Email - проверять формат и существование домена
  - URL - валидировать схему, домен, избегать SSRF
  - Даты - проверять формат и разумность (не в далёком будущем/прошлом)
  - UUID - проверять формат
  - Phone numbers - проверять формат и код страны
  - Postal codes - валидировать по стране

- **Защита от Mass Assignment**
  - Whitelist разрешённых полей для создания/обновления
  - Игнорировать неожиданные поля в запросе
  - Разделять поля доступные для чтения и записи
  - Не позволять изменять системные поля (id, created_at, user_id)

### GraphQL Security

- **Специфичные риски GraphQL**
  - Сложные nested запросы могут вызвать DoS
  - Introspection раскрывает всю схему API
  - Отсутствие встроенного rate limiting
  - N+1 query problem может перегрузить БД
  - Batch атаки через aliases

- **Защита GraphQL API**
  
  Query depth limiting:
  - Ограничить максимальную глубину вложенности запросов (5-10 уровней)
  - Анализировать AST запроса перед выполнением
  - Отклонять слишком глубокие запросы
  
  Query complexity analysis:
  - Назначить стоимость (cost) каждому полю
  - Вычислять общую сложность запроса
  - Устанавливать максимальную сложность
  - Учитывать аргументы (limit, first) в вычислении стоимости
  
  Rate limiting:
  - По IP адресу
  - По API ключу/токену
  - Основанный на complexity score
  - Per-field rate limiting для дорогих операций
  
  Отключение introspection:
  - Отключать на production для публичных API
  - Оставлять для внутренних/dev окружений
  - Использовать для документации только
  
  Дополнительные меры:
  - Timeout для query execution
  - Whitelist разрешённых queries (persisted queries)
  - DataLoader для решения N+1 проблемы
  - Мониторинг медленных запросов
  - Защита от batch атак через aliases

### Безопасность API Response

- **Не раскрывать лишнюю информацию**
  - Минимизировать данные в ответе
  - Не возвращать системные поля (password hashes, internal IDs)
  - Фильтровать поля в зависимости от прав пользователя
  - Использовать projection для выборки только нужных полей

- **Обработка ошибок**
  - Не раскрывать stack traces на production
  - Не раскрывать детали внутренней архитектуры
  - Не раскрывать SQL запросы или database errors
  - Использовать общие сообщения об ошибках для клиента
  - Детальные ошибки логировать на сервере
  - Не различать "user not found" и "wrong password" при входе

- **Pagination защита**
  - Не позволять запрашивать слишком большие страницы
  - Использовать cursor-based pagination для больших datasets
  - Не раскрывать общее количество записей если это конфиденциально
  - Ограничить максимальное количество страниц

### Логирование и мониторинг API

- **Что логировать**
  - Все запросы с timestamp
  - IP адрес клиента, User-Agent
  - Используемый API ключ или user ID
  - Endpoint, HTTP method, status code
  - Время выполнения запроса
  - Ошибки валидации и аутентификации
  - Rate limit violations
  - Подозрительную активность

- **Что НЕ логировать**
  - Пароли и секреты
  - Токены и API ключи (хешировать или маскировать)
  - Персональные данные (PII) - только с согласия и необходимостью
  - Полное тело запроса с чувствительными данными
  - Номера кредитных карт, CVV

- **Мониторинг метрик**
  - Количество запросов в секунду
  - Latency (p50, p95, p99)
  - Error rate по статус кодам
  - Распределение по endpoints
  - Использование API ключей
  - Аномальные паттерны активности

- **Алертинг**
  - Всплески 4xx/5xx ошибок
  - Превышение обычного traffic
  - Медленные endpoints (high latency)
  - Повторяющиеся неудачные попытки аутентификации
  - DDoS паттерны
  - Необычная географическая активность

### API Documentation и Security

- **Документирование безопасности**
  - Чётко описать методы аутентификации
  - Документировать rate limits
  - Указать scope/permissions для endpoints
  - Предоставить примеры правильного использования
  - Описать коды ошибок и их значения

- **Sandbox/Testing окружение**
  - Предоставить тестовое окружение
  - Использовать отдельные ключи для тестирования
  - Не влиять на production данные
  - Ограничить тестовое окружение по IP или другим способом

- **Deprecated API versions**
  - Давать достаточно времени для миграции (6-12 месяцев)
  - Уведомлять через API headers (X-API-Deprecated)
  - Уведомлять через email
  - Документировать migration guide
  - Использовать sunset date в заголовках

---
## CI/CD безопасность

### Безопасность Pipeline

- **Принципы безопасного CI/CD**
  
  **Least Privilege**
  - Pipeline должен иметь минимально необходимые права
  - Разные права для разных этапов (build, test, deploy)
  - Ограничить доступ к production credentials
  
  **Immutability**
  - Артефакты не должны изменяться после создания
  - Использовать content-addressable storage
  - Подписывать артефакты
  - Версионировать все компоненты
  
  **Auditability**
  - Логировать все действия pipeline
  - Хранить историю deployments
  - Отслеживать кто и когда вносил изменения
  - Возможность воспроизвести любой build

- **Защита конфигурации pipeline**
  - Хранить pipeline config в репозитории (GitOps)
  - Code review для изменений в pipeline
  - Ограничить кто может изменять pipeline
  - Использовать protected branches для pipeline файлов
  - Не разрешать pipeline изменять сам себя

- **Изоляция выполнения**
  - Каждый build в изолированном окружении
  - Использовать ephemeral runners/agents
  - Очищать окружение после каждого build
  - Не переиспользовать state между builds
  - Изолировать builds разных проектов

### Secrets Management

- **Типы секретов в CI/CD**
  - API ключи и токены
  - Database credentials
  - SSH ключи
  - Сертификаты и приватные ключи
  - Cloud provider credentials
  - Container registry credentials
  - Signing keys

- **Где НЕ хранить секреты**
  - В исходном коде (hardcoded)
  - В конфигурационных файлах в репозитории
  - В Docker images
  - В логах и артефактах
  - В переменных окружения pipeline без шифрования
  - В комментариях к коду или commits

- **Решения для управления секретами**
  
  **Встроенные в CI/CD платформы**
  - GitHub Secrets (encrypted, per-repo или per-org)
  - GitLab CI/CD Variables (protected, masked)
  - Jenkins Credentials
  - CircleCI Contexts
  
  **Специализированные vault решения**
  - HashiCorp Vault - наиболее популярное решение
  - AWS Secrets Manager
  - Azure Key Vault
  - Google Secret Manager
  - CyberArk
  
  **Kubernetes secrets**
  - Native Kubernetes Secrets (base64, не шифрование!)
  - Sealed Secrets
  - External Secrets Operator
  - SOPS (Mozilla)

- **Best practices для секретов**
  
  **Ротация**
  - Регулярная автоматическая ротация (30-90 дней)
  - Немедленная ротация при подозрении на компрометацию
  - Автоматизировать процесс ротации
  - Минимальный downtime при ротации
  
  **Доступ**
  - Минимально необходимые права доступа
  - Разные секреты для разных окружений
  - Audit log всех обращений к секретам
  - Временные токены вместо долгоживущих
  
  **Защита**
  - Шифрование at rest и in transit
  - Не выводить в логи (masking)
  - Не передавать через command line arguments
  - Использовать short-lived credentials

### Container Security

- **Безопасность Docker images**
  
  **Выбор base image**
  - Использовать official images
  - Предпочитать minimal images (Alpine, distroless)
  - Избегать latest tag, использовать конкретные версии
  - Проверять source и maintainer образа
  - Использовать trusted registries
  
  **Сканирование images**
  - Сканировать на уязвимости перед push
  - Блокировать images с critical/high CVE
  - Регулярно пересканировать существующие images
  - Инструменты: Trivy, Clair, Snyk, Docker Scout
  
  **Минимизация attack surface**
  - Не включать ненужные пакеты
  - Удалять build dependencies в final image
  - Использовать multi-stage builds
  - Не включать secrets в image layers
  - Удалять cache и временные файлы

- **Dockerfile best practices**
  
  **Пользователь и права**
  - Не запускать процессы от root
  - Создавать dedicated user для приложения
  - Использовать USER directive
  - Минимальные права на файлы
  
  **Безопасная конфигурация**
  - Использовать COPY вместо ADD
  - Указывать конкретные файлы, не wildcard
  - Не использовать privileged mode
  - Ограничить capabilities
  - Использовать read-only filesystem где возможно
  
  **Оптимизация layers**
  - Группировать RUN commands
  - Очищать cache в том же layer
  - Использовать .dockerignore
  - Не копировать .git, node_modules, и т.д.

- **Container Runtime Security**
  
  **Ограничения ресурсов**
  - CPU и memory limits
  - Ограничение количества процессов
  - Ограничение сетевого bandwidth
  
  **Изоляция**
  - Network policies для ограничения трафика
  - Не использовать host network без необходимости
  - Не монтировать Docker socket в контейнер
  - Использовать seccomp profiles
  - AppArmor или SELinux profiles
  
  **Secrets в runtime**
  - Передавать через environment variables или mounted secrets
  - Не bake secrets в image
  - Использовать tmpfs для sensitive data
  - Ротация secrets без перезапуска контейнера

- **Container Registry Security**
  - Использовать private registry для production images
  - Аутентификация для push и pull
  - Сканирование images в registry
  - Подпись images (Docker Content Trust, Cosign)
  - Retention policies для старых images
  - Geo-replication для disaster recovery

### Dependency Scanning в CI/CD

- **Интеграция сканирования в pipeline**
  
  **На этапе build**
  - npm audit / yarn audit для JavaScript
  - composer audit для PHP
  - pip-audit для Python
  - bundler-audit для Ruby
  - OWASP Dependency-Check (универсальный)
  
  **Настройка порогов**
  - Определить severity threshold для блокировки build
  - Critical - всегда блокировать
  - High - блокировать на production
  - Medium/Low - warning, не блокировать
  - Исключения для false positives с документацией

- **Автоматическое обновление зависимостей**
  
  **Инструменты**
  - Dependabot (GitHub)
  - Renovate (универсальный)
  - Snyk
  
  **Конфигурация**
  - Автоматические PR для security updates
  - Группировка minor/patch updates
  - Расписание проверок (ежедневно, еженедельно)
  - Автоматический merge для patch versions (опционально)
  - Обязательные тесты перед merge

- **Software Bill of Materials (SBOM)**
  - Генерировать SBOM для каждого release
  - Форматы: SPDX, CycloneDX
  - Хранить вместе с артефактами
  - Инструменты: Syft, Trivy, SPDX tools
  - Позволяет быстро реагировать на новые CVE

### License Compliance

- **Зачем отслеживать лицензии**
  - Юридические риски нарушения лицензий
  - Copyleft лицензии (GPL) могут требовать открытия кода
  - Некоторые лицензии несовместимы друг с другом
  - Compliance требования от клиентов

- **Типы лицензий и их риски**
  
  **Permissive (низкий риск)**
  - MIT, BSD, Apache 2.0
  - Можно использовать в коммерческих продуктах
  - Минимальные требования
  
  **Copyleft (высокий риск)**
  - GPL, LGPL, AGPL
  - Могут требовать открытия производного кода
  - AGPL распространяется на network use
  - Требуют внимательного анализа
  
  **Commercial / Proprietary**
  - Требуют покупки лицензии
  - Ограничения на redistribution
  - Проверять условия использования

- **Автоматизация license compliance**
  
  **Инструменты**
  - FOSSA
  - WhiteSource / Mend
  - Snyk License Compliance
  - License Finder
  - npm license-checker
  
  **Процесс**
  - Определить policy разрешённых лицензий
  - Автоматическая проверка в CI/CD
  - Блокировать build при нарушении policy
  - Процесс одобрения исключений
  - Генерация attribution files

### Pipeline Security Gates

- **Обязательные проверки перед deploy**
  
  **Code Quality**
  - Linting и formatting
  - Static code analysis
  - Code coverage threshold
  - Complexity metrics
  
  **Security**
  - SAST scanning
  - Dependency vulnerability check
  - Container image scanning
  - License compliance
  - Secrets detection
  
  **Testing**
  - Unit tests
  - Integration tests
  - Security tests (если есть)
  - Performance tests (для production)
  
  **Approvals**
  - Code review approval
  - Security team approval (для критичных изменений)
  - Change management approval (для production)

- **Branch Protection**
  - Требовать pull request для merge
  - Минимальное количество approvals
  - Требовать passing status checks
  - Запретить force push
  - Require signed commits (опционально)
  - Dismiss stale approvals при новых commits
  - Restrict who can push to protected branches

- **Environment Protection**
  - Разные правила для разных окружений
  - Production требует дополнительных approvals
  - Ограничить кто может deploy на production
  - Required reviewers для production deployments
  - Wait timer перед deploy (deployment window)

### Secrets Detection

- **Что искать в коде**
  - API ключи и токены
  - Passwords
  - Private keys (RSA, SSH, PGP)
  - Connection strings
  - AWS/GCP/Azure credentials
  - JWT secrets
  - Webhook URLs с токенами

- **Инструменты для обнаружения секретов**
  
  **Pre-commit hooks**
  - git-secrets
  - pre-commit framework с detect-secrets
  - Husky + секрет-сканер
  
  **CI/CD integration**
  - GitLeaks
  - TruffleHog
  - detect-secrets (Yelp)
  - GitHub Secret Scanning
  - GitLab Secret Detection
  
  **Рекомендации**
  - Сканировать всю историю git, не только текущий commit
  - Использовать pre-commit hooks для раннего обнаружения
  - Интегрировать в CI/CD pipeline
  - Настроить custom patterns для специфичных секретов
  - Немедленно ротировать обнаруженные секреты

### Signed Commits и Artifacts

- **Подпись Git commits**
  
  **Зачем подписывать**
  - Гарантия авторства commit
  - Защита от подмены истории
  - Compliance требования
  - Цепочка доверия от разработчика до production
  
  **Способы подписи**
  - GPG ключи (традиционный)
  - SSH ключи (GitHub, GitLab поддерживают)
  - S/MIME сертификаты
  
  **Внедрение**
  - Сгенерировать ключи для каждого разработчика
  - Загрузить публичные ключи в Git платформу
  - Настроить git config для автоматической подписи
  - Включить verified badge отображение
  - Рассмотреть требование signed commits для protected branches

- **Подпись артефактов**
  
  **Container images**
  - Docker Content Trust (DCT)
  - Cosign (Sigstore)
  - Notary
  
  **Бинарные артефакты**
  - GPG подпись
  - Code signing certificates
  - Checksums (SHA256) как минимум
  
  **Верификация**
  - Проверять подпись перед deployment
  - Отклонять неподписанные артефакты на production
  - Хранить публичные ключи в безопасном месте

### Infrastructure as Code Security

- **Сканирование IaC**
  
  **Что проверять**
  - Terraform, CloudFormation, Pulumi
  - Kubernetes manifests
  - Ansible playbooks
  - Docker Compose files
  
  **Типичные проблемы**
  - Публичный доступ к S3 buckets
  - Security groups с 0.0.0.0/0
  - Отсутствие шифрования
  - Hardcoded secrets
  - Отсутствие logging
  - Избыточные IAM permissions
  
  **Инструменты**
  - Checkov (универсальный)
  - tfsec (Terraform)
  - terrascan
  - KICS (Checkmarx)
  - Snyk IaC
  - AWS CloudFormation Guard

- **Policy as Code**
  - Open Policy Agent (OPA)
  - Sentinel (HashiCorp)
  - Kyverno (Kubernetes)
  - Определять security policies как код
  - Автоматическая проверка compliance
  - Блокировать non-compliant deployments

### Deployment Security

- **Стратегии безопасного deployment**
  
  **Blue-Green Deployment**
  - Две идентичные production среды
  - Мгновенное переключение трафика
  - Быстрый rollback при проблемах
  - Возможность тестирования перед switch
  
  **Canary Deployment**
  - Постепенное раскатывание на часть пользователей
  - Мониторинг метрик и ошибок
  - Автоматический rollback при аномалиях
  - Снижение риска массового impact
  
  **Rolling Deployment**
  - Постепенная замена instances
  - Без downtime
  - Возможность остановить при проблемах

- **Rollback процедуры**
  - Автоматизировать rollback
  - Тестировать rollback регулярно
  - Хранить предыдущие версии артефактов
  - Документировать процедуру ручного rollback
  - Определить критерии для автоматического rollback

- **Post-deployment verification**
  - Smoke tests после deployment
  - Health checks
  - Мониторинг ключевых метрик
  - Сравнение с baseline
  - Alerts на аномалии

### Audit и Compliance в CI/CD

- **Что логировать**
  - Все запуски pipeline
  - Кто инициировал build/deploy
  - Какие изменения включены
  - Результаты security checks
  - Approvals и rejections
  - Доступ к secrets
  - Изменения в pipeline конфигурации

- **Retention политики**
  - Хранить логи минимум 1 год
  - Build артефакты для production releases
  - Audit trail для compliance
  - Соответствие регуляторным требованиям

- **Compliance controls**
  - Separation of duties (разработчик не может deploy)
  - Mandatory code review
  - Approved tools и dependencies
  - Change management процесс
  - Documentation requirements
---

## Мониторинг и реагирование

### Логирование событий безопасности

- **Что обязательно логировать**
  
  **Аутентификация и авторизация**
  - Успешные и неуспешные попытки входа
  - Выход из системы
  - Смена пароля
  - Сброс пароля (запрос и выполнение)
  - Включение/отключение 2FA
  - Неудачные попытки авторизации (доступ к ресурсу без прав)
  - Повышение привилегий
  - Изменение ролей пользователей
  
  **Управление пользователями**
  - Создание новых пользователей
  - Удаление пользователей
  - Изменение email или username
  - Блокировка/разблокировка аккаунтов
  - Изменение критичных настроек профиля
  
  **Административные действия**
  - Вход в административную панель
  - Изменения конфигурации системы
  - Изменения прав доступа
  - Создание/изменение API ключей
  - Изменения в настройках безопасности
  
  **Операции с данными**
  - Массовое удаление данных
  - Экспорт чувствительных данных
  - Доступ к персональным данным (PII)
  - Изменения в критичных таблицах
  
  **Системные события**
  - Запуск и остановка сервисов
  - Изменения в конфигурационных файлах
  - Ошибки приложения и исключения
  - Подозрительные SQL запросы
  - Rate limit violations

- **Что включать в лог запись**
  
  Обязательные поля:
  - Timestamp в UTC (ISO 8601 формат)
  - Уровень важности (severity): DEBUG, INFO, WARNING, ERROR, CRITICAL
  - Тип события (event type)
  - User ID или идентификатор сессии
  - IP адрес источника
  - User-Agent
  - Результат операции (success/failure)
  - Уникальный идентификатор запроса (request ID) для трассировки
  
  Дополнительные поля (в зависимости от события):
  - URL и HTTP метод
  - Параметры запроса (без чувствительных данных)
  - ID затронутого ресурса
  - Предыдущее и новое значение (для изменений)
  - Причина ошибки или отказа
  - Геолокация по IP

- **Что НЕ логировать**
  - Пароли (даже хешированные)
  - Токены и API ключи (маскировать: xxxx...last4)
  - Полные номера кредитных карт (только last4)
  - CVV коды
  - Персональные данные без необходимости
  - Медицинская информация
  - Биометрические данные
  - Содержимое приватных сообщений

- **Структурированное логирование**
  - Использовать JSON формат для машинной обработки
  - Единый формат для всех сервисов
  - Включать контекст для correlation
  - Избегать многострочных лог записей
  - Использовать стандартные уровни severity

### Централизованное управление логами

- **Архитектура системы логирования**
  
  Компоненты:
  - **Сбор** - агенты на серверах (Filebeat, Fluentd, rsyslog)
  - **Транспорт** - очереди сообщений (Kafka, Redis)
  - **Обработка** - парсинг и обогащение (Logstash, Fluentd)
  - **Хранение** - база данных логов (Elasticsearch, ClickHouse)
  - **Визуализация** - интерфейс поиска и дашборды (Kibana, Grafana)
  
  Популярные стеки:
  - ELK Stack (Elasticsearch, Logstash, Kibana)
  - EFK Stack (Elasticsearch, Fluentd, Kibana)
  - Grafana Loki + Promtail
  - Graylog
  - Splunk (коммерческий)

- **Требования к системе логирования**
  - Надёжная доставка логов (at-least-once)
  - Защита от потери логов при сбоях
  - Масштабируемость по объёму данных
  - Быстрый поиск по логам
  - Долгосрочное хранение (compliance требования)
  - Контроль доступа к логам
  - Целостность логов (защита от модификации)

- **Хранение и ротация логов**
  - Определить retention policy (сколько хранить)
  - Hot/warm/cold архитектура для оптимизации хранения
  - Сжатие старых логов
  - Архивирование в cold storage (S3, Glacier)
  - Соответствие требованиям регуляторов (GDPR, PCI DSS)
  - Типичные сроки: 90 дней hot, 1 год warm, 7 лет archive

### SIEM системы (Security Information and Event Management)

- **Что такое SIEM**
  - Централизованный сбор security событий
  - Корреляция событий из разных источников
  - Обнаружение аномалий и угроз
  - Автоматические алерты
  - Forensic анализ и расследование инцидентов
  - Compliance отчётность

- **Популярные SIEM решения**
  
  Open Source:
  - Wazuh (OSSEC fork) - бесплатный, хорошая функциональность
  - Security Onion - комплексное решение
  - OSSIM (AlienVault Open Source)
  
  Коммерческие:
  - Splunk Enterprise Security
  - IBM QRadar
  - Microsoft Sentinel
  - Elastic Security
  - Sumo Logic

- **Источники данных для SIEM**
  - Логи веб-серверов (Apache, Nginx)
  - Логи приложений
  - Логи баз данных
  - Логи аутентификации (SSH, VPN, AD)
  - Firewall логи
  - IDS/IPS алерты
  - Endpoint security
  - Cloud provider логи (AWS CloudTrail, Azure Activity Log)
  - Network flow data

- **Правила корреляции и обнаружения**
  
  Типичные сценарии:
  - Множественные неудачные попытки входа с одного IP
  - Успешный вход после серии неудачных попыток
  - Вход из необычной геолокации
  - Одновременный вход из разных локаций
  - Доступ к sensitive данным в нерабочее время
  - Массовая загрузка или экспорт данных
  - Privilege escalation attempts
  - SQL injection паттерны в логах
  - Brute force атаки

### Алерты и уведомления

- **Уровни критичности алертов**
  
  **Critical (P1)**
  - Требует немедленной реакции (в течение минут)
  - Активная атака или компрометация
  - Полный отказ критичного сервиса
  - Утечка данных
  - Уведомление: звонок, SMS, push
  
  **High (P2)**
  - Требует быстрой реакции (в течение часа)
  - Подозрительная активность высокого риска
  - Частичный отказ сервиса
  - Уведомление: SMS, email, Slack
  
  **Medium (P3)**
  - Требует реакции в рабочее время
  - Аномалии требующие расследования
  - Уведомление: email, Slack
  
  **Low (P4)**
  - Информационные алерты
  - Тренды и статистика
  - Уведомление: email digest, dashboard

- **Каналы уведомлений**
  - Email - для несрочных алертов
  - Slack/Teams - для командной работы
  - PagerDuty/OpsGenie - для on-call ротации
  - SMS - для критичных алертов
  - Телефонный звонок - для P1 инцидентов
  - Push notifications - мобильное приложение

- **Предотвращение alert fatigue**
  - Настроить правильные пороги срабатывания
  - Группировать связанные алерты
  - Использовать escalation policies
  - Регулярно пересматривать и тюнить правила
  - Удалять или исправлять noisy алерты
  - Документировать runbooks для каждого типа алерта
  - Измерять signal-to-noise ratio

- **On-call ротация**
  - Определить расписание дежурств
  - Настроить escalation при отсутствии ответа
  - Документировать процедуры реагирования
  - Регулярные учения и тренировки
  - Post-incident reviews для улучшения процессов

### Security Scanning

- **SAST (Static Application Security Testing)**
  
  Что это:
  - Анализ исходного кода без выполнения
  - Поиск уязвимостей на этапе разработки
  - Интеграция в IDE и CI/CD
  
  Что находит:
  - SQL injection
  - XSS уязвимости
  - Hardcoded credentials
  - Небезопасные функции
  - Buffer overflows
  - Path traversal
  
  Инструменты:
  - SonarQube (универсальный)
  - Semgrep (open source, быстрый)
  - Bandit (Python)
  - Brakeman (Ruby on Rails)
  - PHPStan, Psalm (PHP)
  - ESLint security plugins (JavaScript)
  - CodeQL (GitHub)
  
  Рекомендации:
  - Интегрировать в CI/CD pipeline
  - Блокировать merge при critical findings
  - Регулярно обновлять правила
  - Настроить исключения для false positives
  - Обучать разработчиков исправлять найденное

- **DAST (Dynamic Application Security Testing)**
  
  Что это:
  - Тестирование работающего приложения
  - Имитация атак извне (black box)
  - Поиск runtime уязвимостей
  
  Что находит:
  - Уязвимости в конфигурации
  - Проблемы аутентификации
  - Session management issues
  - Injection уязвимости в runtime
  - Misconfiguration
  
  Инструменты:
  - OWASP ZAP (бесплатный)
  - Burp Suite (коммерческий, industry standard)
  - Nikto (web server scanner)
  - Nuclei (template-based scanner)
  - Acunetix (коммерческий)
  
  Рекомендации:
  - Запускать на staging environment
  - Использовать authenticated scanning
  - Интегрировать в CI/CD (на stage)
  - Не запускать на production без согласования
  - Комбинировать с SAST для полного покрытия

- **SCA (Software Composition Analysis)**
  
  Что это:
  - Анализ зависимостей проекта
  - Поиск известных уязвимостей (CVE)
  - Проверка лицензий
  
  Инструменты:
  - npm audit / yarn audit (JavaScript)
  - Composer audit (PHP)
  - pip-audit, Safety (Python)
  - OWASP Dependency-Check
  - Snyk (универсальный)
  - GitHub Dependabot
  - WhiteSource / Mend
  
  Рекомендации:
  - Автоматическое сканирование при каждом build
  - Блокировать build при critical/high CVE
  - Автоматические PR для обновления зависимостей
  - Регулярный аудит даже без изменений кода

- **Container Security Scanning**
  - Trivy (универсальный, популярный)
  - Clair (CoreOS)
  - Anchore
  - Docker Scout
  - Проверять base images на уязвимости
  - Сканировать перед push в registry

### Penetration Testing

- **Виды пентестов**
  
  **Black Box**
  - Тестировщик не знает о системе ничего
  - Имитация внешнего злоумышленника
  - Наиболее реалистичный сценарий
  
  **White Box**
  - Тестировщик имеет полный доступ к коду и документации
  - Более глубокий анализ
  - Находит больше уязвимостей
  
  **Gray Box**
  - Частичная информация о системе
  - Компромисс между реализмом и глубиной
  - Часто используется для web приложений

- **Scope и планирование**
  - Определить границы тестирования
  - Согласовать временные рамки
  - Исключить production если возможно
  - Уведомить провайдеров (хостинг)
  - Подготовить тестовые аккаунты
  - Определить правила engagement
  - Согласовать каналы коммуникации

- **Частота проведения**
  - Минимум раз в год для критичных систем
  - После значительных изменений
  - При добавлении новой функциональности
  - После security инцидентов

- **Отчётность и remediation**
  - Получить детальный отчёт с severity ratings
  - Приоритизировать исправления
  - Установить сроки для каждой severity
  - Critical/High - исправить немедленно
  - Medium - исправить в следующем релизе
  - Low - запланировать в backlog
  - Провести re-test после исправлений
---