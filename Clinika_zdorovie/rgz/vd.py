import sqlite3

# Устанавливаем соединение с базой данных
conn = sqlite3.connect('blog.db')
c = conn.cursor()

# Выполняем запрос к базе данных
c.execute('SELECT * FROM users_identification')

# Получаем все строки результата
rows = c.fetchall()

# Выводим результат
for row in rows:
    print(row)

# Закрываем соединение
conn.close()