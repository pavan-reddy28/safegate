

proxy_http_version 1.1;



proxy_set_header Host $host;



proxy_set_header X-Real-IP $remote_addr;



proxy_set_header X-Forwarded-For "";



proxy_set_header X-Forwarded-Proto $scheme;



proxy_set_header X-Forwarded-Host $host;



# Backend creates its own request ID.

proxy_set_header X-Request-ID "";



proxy_set_header Connection "";



proxy_connect_timeout 5s;



proxy_send_timeout 30s;



proxy_read_timeout 30s;



proxy_hide_header Server;



proxy_hide_header X-Powered-By;



# Nginx provides the authoritative versions.

proxy_hide_header X-Content-Type-Options;



proxy_hide_header Referrer-Policy;



proxy_hide_header X-Frame-Options;


