from flask import Flask, render_template, flash ,url_for, request , redirect , abort
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin ,login_user, login_required, logout_user, current_user ,LoginManager
from functools import wraps
import os

DB_NAME = "database.db" 

# Create the Flask application

app = Flask(__name__, template_folder='templates')

app.config['SECRET_KEY'] = 'secret'
app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "website_db"

mysql = MySQL(app)

#Function add user to database
def add_user_to_db(cur,first_name,last_name,email,password) :
    hash_password=generate_password_hash(password , method='pbkdf2:sha256' )
    cur.execute(""" insert into Users (first_name, last_name ,email ,password)
                values (%s, %s, %s, %s)
                """,  (first_name, last_name, email, hash_password))
    mysql.connection.commit()

#Check the email typed does exist in the database or not
def duplicate_email_check(cur,email) :
    cur.execute(""" select email from Users order by email asc""")
    emails=cur.fetchall()
    for e_mail in emails :
        if email == e_mail : return True
    return False

def add_prodcut(title,category,price,image_path) :
    conn=mysql.connection
    cur=conn.cursor()
    cur.execute("insert into produits (title, category, price, image_path) VALUES (%s, %s, %s, %s)" , ((title, category, price, image_path)))
    conn.commit()
    cur.close()
    
def delete_product_db(product_id) :
    conn=mysql.connection
    cur=conn.cursor()
    cur.execute("select image_path from produits where ID=%s" ,(product_id,))
    image_path=cur.fetchone()[0]
    image_path = os.path.join(app.root_path,"static\\assets\\product_images\\",image_path[22:])
    os.remove(image_path)
    cur.execute("delete from produits where ID=%s" ,(product_id,))
    conn.commit()    
    cur.close()
    flash("Product deleted successfully" ,category="success")


#User_class

class User(UserMixin) :
    def __init__(self, id, email,user_type,hashed_password):
        self.id = id
        self.email = email
        self.user_type = user_type
        self.is_admin= (user_type == "Admin")
        self.hashed_password=hashed_password

# Initialize the LoginManager

login_manager = LoginManager()
login_manager.init_app(app)

# Set the login view
login_manager.login_view = 'login'  # The name of the login route

# Create the user loader function
@login_manager.user_loader
def load_user(user_id):
    # Connect to your MySQL database and retrieve the user by ID
    cursor = mysql.connection.cursor()

    # Execute the query to get the user by id
    cursor.execute("SELECT id, email, user_type , password FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        user = User(id=user_data[0], email=user_data[1], user_type=user_data[2] , hashed_password=user_data[3])
        return user
    return None

#Function admin required

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_admin :
            pass
        else :
            abort(403)  # Forbidden access
        return f(*args, **kwargs)
    return decorated_function



#defining Routes        
@app.route('/')
def home ():
    return redirect(url_for('home_page'))

 
# Home_page route
categories = ["T-shirts" ,"Jeans" ,"Jackets" ,"Shoes" , "Accessories" ]
@app.route('/home_page')
@app.route('/home_page/search/<search>')
@app.route('/home_page/filter/<category>')
@login_required
def home_page(category='ALL' , search = ''):
    cur=mysql.connection.cursor()
    if search :
        search_query=request.args.get("product_name")   
        print(search_query)
        query ="""select title, price,image_path from produits where title like  %s"""  
        cur.execute(query ,("%" + search_query + "%",))
        produits = cur.fetchall()
    else :  
        if category=='ALL':
            cur.execute("""select title, price,image_path from produits""")
            produits=cur.fetchall()
        else:
            cur.execute("""select title, price,image_path from produits where category = %s""" , (category,))
            produits=cur.fetchall()
            
    cur.close()        
    return render_template("home_page.html",produits=produits ,categories=categories )    
        
    
#admin-dashboard


@app.route('/admin_dashboard' ,methods=['GET'])
@app.route('/admin_dashboard/search/<search>')
@app.route('/admin_dashboard/filter/<category>')
@login_required
@admin_required
def admin_dashboard(category='ALL' ,search=''):
    cur=mysql.connection.cursor()   
    if search :
        search_query=request.args.get("product_name")   
        print(search_query)
        query ="""select title, price,image_path , ID from produits where title like  %s"""  
        cur.execute(query ,("%" + search_query + "%",))
        produits = cur.fetchall()
    else : 
        if category =='ALL':
            cur.execute("""select title, price,image_path ,ID from produits""")
            produits=cur.fetchall()
        else:
            cur.execute("""select title, price,image_path from produits where category = %s""" , (category,))
            produits=cur.fetchall()
    
    cur.close()
    return render_template("admin_dashboard.html",produits=produits ,categories=categories )
        

#---------------------------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------User Inscription-------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------------------------


# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        #cursor intialisation
        cur = mysql.connection.cursor()
        cur.execute(""" select id , email , password  ,user_type from users
                    where email = %s
                    """, (email ,) )
        values =cur.fetchall()
        cur.close()
        if values == []:
            flash("the email cannot be found" , category="Error")
        else :
            password_check = check_password_hash(values[0][2] ,password)
            if password_check :
                flash("Logged in successfully" , category="success")
                user = User(id=values[0][0], email=values[0][1],user_type=values[0][3] ,hashed_password = values[0][2] )
                login_user(user ,remember=True)
                return redirect(url_for('home_page'))
            else :
                flash("the password is incorrect" , category="Error")  
    return render_template('login.html')


# Logout route
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

# Sign-Up route
@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        password_1 = request.form.get('password_1')
        password_2 = request.form.get('password_2')
        
        if len(email) < 4:
            flash("Email must be greater than 3 characters", category='Error')
        elif len(first_name) < 2:
            flash("The first name must be greater than 1 character", category='Error')
        elif len(last_name) < 2:
            flash("The last name must be greater than 1 character", category='Error')
        elif password_1 != password_2:
            flash("Passwords don't match", category='Error')
        elif len(password_1) < 8:
            flash("Password must be at least 8 characters", category='Error')
        else:
            #cursor intialisation
            cur = mysql.connection.cursor()
            check = duplicate_email_check(cur,email)
            
            if check : #the email written is used by another user !
                flash("The email is choosen by another user !", category='Error')
                return render_template('sign_up.html')
            else :
                add_user_to_db(cur,first_name,last_name,email,password_1)
            cur.close()
            flash('Account created!', category='Success')
            return redirect('login')
    return render_template('sign_up.html')

#---------------------------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------Admin Management-------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------------------------

@app.route('/add_admin' , methods=['GET' , 'POST'])
@login_required
@admin_required
def add_admin() :
    if request.method == 'POST' :
        email = request.form.get('email')
        password = request.form.get('password')
        #cursor intialisation
        conn= mysql.connection
        cur = conn.cursor()
        
        #admin password verification
        password_check = check_password_hash(current_user.hashed_password , password)
        if password_check :
            cur.execute("select * from users where email=%s",(email,))
            email_exist=cur.fetchall()
            if email_exist :
                cur.execute("""  
                            UPDATE `users` SET `user_type` = 'Admin' WHERE `users`.`email` = %s
                            """ ,(email,))
                conn.commit()
                cur.close()
                flash("Added succesfully " + email, category='Success')
            else :
                flash("The email written doesn't exist !", category='Error')
        else :
            flash("Wrong Password !!",category='Error')
        return redirect('admin_dashboard')
        
            
    return render_template('add_admin.html')

#---------------------------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------Products Management-------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------------------------

#create product route 
@app.route('/create_product', methods=['GET', 'POST'])
@login_required
@admin_required
def create_product():
    if request.method =='POST' :
        title = request.form.get('title')
        category = request.form.get('category')
        price = request.form.get('price')
        image = request.files.get('image')
        image.save(f'static/assets/product_images/{image.filename}')
        image_path= f"assets/product_images/{image.filename}"
        add_prodcut(title,category,price,image_path)
        flash("Added succesfully " ,category='Success')
        return redirect("/admin_dashboard")
    
    return render_template('create_product.html')


#delete product process
@app.route('/delete_product/<int:item_id>')
@login_required
@admin_required
def delete_product(item_id) :
    #cursor intialisation
    delete_product_db(item_id)
    return redirect('/admin_dashboard')

# Main entry point
if __name__ == '__main__':
    app.run(debug=True)
