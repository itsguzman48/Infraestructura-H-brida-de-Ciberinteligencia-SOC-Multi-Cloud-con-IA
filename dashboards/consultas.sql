-- Panel 1: Tabla comandos recientes (ajuste horario local)
SELECT datetime(timestamp, 'localtime') AS Fecha,
       ip AS Atacante, location AS Origen, input AS Comando
FROM events WHERE event_type = 'COMMAND'
ORDER BY timestamp DESC LIMIT 15;

-- Panel 2: Distribucion geografica (Donut Chart)
SELECT location AS Origen, COUNT(*) AS Total
FROM events WHERE event_type = 'COMMAND'
GROUP BY location ORDER BY Total DESC;

-- Panel 3: Top contrasenas fuerza bruta (Bar Chart)
SELECT password AS Contrasena, COUNT(*) AS Total
FROM events WHERE event_type = 'FAILED' AND password != '???'
GROUP BY password ORDER BY Total DESC LIMIT 5;