import sqlite3

connection = sqlite3.connect("database/database.db")

with open("database/schema.sql") as f:
    connection.executescript(f.read())

connection.commit()
connection.close()

print("Database Created Successfully")