# Запуск в Docker

Этот проект упакован в Docker. Neo4j запускается как отдельный контейнер.

### Состав
- `app` — python-приложение на FastAPI с клиентской частью на JS
- `gnn` — сервис для запуска GNN и стриминга логов
- `neo4j` — база данных Neo4j

### Быстрый старт
1) Скопируйте пример переменных и при необходимости отредактируйте:
   cp .env.example .env

   Обязательно задайте пароль для Neo4j. Установите `NEO4J_AUTH`, `NEO4J_USER` и `NEO4J_PASSWORD` в `.env`.

2) Запустите Docker Compose из корня проекта:
   
   `docker compose up --build`

3) Откройте UI:
   http://localhost:8000/

4) При необходимости можно открыть Neo4j Browser: http://localhost:7474/ (учётные данные берутся из `.env`)

### Заметки
- Контейнер приложения подключается к Neo4j по адресу `bolt://neo4j:7687` (имя сервиса).
- Контейнер приложения обращается к GNN сервису по адресу `http://gnn:8001` (имя сервиса).
- Загрузчики можно запустить и вручную внутри контейнера, пример:
  
  `docker exec -it scenario_app python -u data_collection/loader.py --only techniques,capec,cwe,cve --cve-from-year 2020`
- Для сборки используются `requirements-app.txt`, `requirements-gnn.txt` и `requirements-gnn-service.txt`.

## Команды Compose

- up — сборка (при необходимости) и запуск сервисов
  - В фоне: `docker compose up -d --build`
  - Пересобрать без кеша: `docker compose build --no-cache app`

- stop — остановить запущенные контейнеры, НО не удалять их
  - Данные в томах (`neo4j_data`, `neo4j_logs`) сохраняются
  - Возобновить: `docker compose start`

- start — запустить ранее остановленные контейнеры

- restart — перезапустить конкретный сервис
  - Пример: `docker compose restart app`

- down — остановить и удалить контейнеры, сеть и артефакты запуска
  - Тома остаются, если не указать `-v`
  - Полная очистка с удалением томов (стирает БД):
    `docker compose down -v`
  - Удалить образы: `docker compose down --rmi all`
  - Удалить "осиротевшие" контейнеры: `docker compose down --remove-orphans`

- logs — посмотреть логи
  - Все: `docker compose logs -f`
  - По сервису: `docker compose logs -f app`

- exec — выполнить команду внутри контейнера
  - Пример: `docker compose exec app bash`
  - Коротко по имени контейнера: `docker exec -it scenario_app bash`
