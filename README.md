using Microsoft.Data.SqlClient;
using System;




        string connectionString =
    "Server=localhost,1433;" +
    "Database=master;" +
    "User Id=sa;" +
    "Password=Password123!;" +
    "TrustServerCertificate=True;";

        string sql = @"
            SELECT *
            FROM TestCodes;";

        using SqlConnection connection = new(connectionString);
        connection.Open();
        using SqlCommand command = new(sql, connection);
        using SqlDataReader reader = command.ExecuteReader();

        int row = 0;

        while (reader.Read())
        {
            row++;

            Console.WriteLine(
                $"Row {row}: " +
                $"Id={reader["Id"]}, " +
                $"Code={reader["Code"]}, " +
                $"Description={reader["Description"]}");
        }
        Console.WriteLine($"The total number of row is: {row}");
