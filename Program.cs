using Npgsql;
using System.Security.Cryptography;
using System.Text;

record User(string Username, string PasswordHash);

interface IAuthSystem
{
    bool Login(string username, string password);
    void Logout();
    void Register(string username, string password);
    void ResetPassword(string username, string newPassword);
}

internal class ConnectedService
{
    public readonly string connectionString = "your_connection_string_here";

    public void ExecuteNonQuery(
        string query,
        Dictionary<string, object> parameters)
    {
        using NpgsqlConnection connection = new NpgsqlConnection(connectionString);
        connection.Open();

        using var command = new NpgsqlCommand();
        command.Connection = connection;
        command.CommandText = query;

        if (parameters != null)
        {
            foreach (var parameter in parameters)
            {
                command.Parameters.AddWithValue(parameter.Key, parameter.Value);
            }
        }

        command.ExecuteNonQuery();
    }
}

class AuthenticationSystem : ConnectedService, IAuthSystem
{
    public void Register(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Username and password cannot be empty.");
        }

        if (UserExists(username))
        {
            throw new ArgumentException("Username already exists.");
        }

        string salt = GenerateSalt();
        string passwordHash = GeneratePasswordHash(password, salt);

        string query = "INSERT INTO users (username, password_hash) VALUES (@username, @passwordHash)";
        Dictionary<string, object> parameters = new Dictionary<string, object>
        {
            { "username", username },
            { "passwordHash", passwordHash }
        };

        ExecuteNonQuery(query, parameters);
    }

    public bool Login(string username, string password)
    {
        if (!UserExists(username))
        {
            return false;
        }

        string storedPasswordHash;

        string query = "SELECT password_hash FROM users WHERE username = @username";
        Dictionary<string, object> parameters = new Dictionary<string, object>
        {
            { "username", username }
        };

        using (var connection = new NpgsqlConnection(connectionString))
        {
            connection.Open();

            using (var command = new NpgsqlCommand())
            {
                command.Connection = connection;
                command.CommandText = query;
                command.Parameters.AddWithValue("username", username);
                storedPasswordHash = command.ExecuteScalar()?.ToString();
            }
        }

        string passwordHash = GeneratePasswordHash(password, storedPasswordHash.Substring(0, 16));

        return storedPasswordHash == passwordHash;
    }

    public void Logout()
    {
        // Perform any necessary logout operations
    }

    public void ResetPassword(string username, string newPassword)
    {
        if (!UserExists(username))
        {
            throw new ArgumentException("Invalid username.");
        }

        string salt = GenerateSalt();
        string passwordHash = GeneratePasswordHash(newPassword, salt);

        string query = "UPDATE users SET password_hash = @passwordHash WHERE username = @username";
        Dictionary<string, object> parameters = new Dictionary<string, object>
        {
            { "passwordHash", passwordHash },
            { "username", username }
        };

        ExecuteNonQuery(query, parameters);
    }

    private string GenerateSalt()
    {
        byte[] saltBytes = new byte[16];
        using (var rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(saltBytes);
        }

        return Convert.ToBase64String(saltBytes);
    }

    private string GeneratePasswordHash(string password, string salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] saltBytes = Convert.FromBase64String(salt);

        byte[] combinedBytes = new byte[saltBytes.Length + passwordBytes.Length];
        Buffer.BlockCopy(saltBytes, 0, combinedBytes, 0, saltBytes.Length);
        Buffer.BlockCopy(passwordBytes, 0, combinedBytes, saltBytes.Length, passwordBytes.Length);

        using (var sha256 = SHA256.Create())
        {
            byte[] hashBytes = sha256.ComputeHash(combinedBytes);
            return Convert.ToBase64String(hashBytes);
        }
    }

    private bool UserExists(string username)
    {
        using (var connection = new NpgsqlConnection(connectionString))
        {
            connection.Open();

            using (var command = new NpgsqlCommand())
            {
                command.Connection = connection;
                command.CommandText = "SELECT COUNT(*) FROM users WHERE username = @username";
                command.Parameters.AddWithValue("username", username);
                int count = Convert.ToInt32(command.ExecuteScalar());

                return count > 0;
            }
        }
    }
}

class Program
{
    static void Main(string[] args)
    {
        IAuthSystem authSystem = new AuthenticationSystem();

        // Register a new user
        try
        {
            authSystem.Register("john", "password123");
            Console.WriteLine("Registration successful.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Registration failed: " + ex.Message);
        }

        // Login with valid credentials
        bool loggedIn = authSystem.Login("john", "password123");
        Console.WriteLine("Login successful: " + loggedIn);

        // Login with invalid credentials
        loggedIn = authSystem.Login("john", "wrongpassword");
        Console.WriteLine("Login successful: " + loggedIn);

        // Reset password
        try
        {
            authSystem.ResetPassword("john", "newpassword456");
            Console.WriteLine("Password reset successful.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Password reset failed: " + ex.Message);
        }

        // Login with new password
        loggedIn = authSystem.Login("john", "newpassword456");
        Console.WriteLine("Login successful: " + loggedIn);
    }
}
