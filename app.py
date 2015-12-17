import os
import os.path as op
from datetime import datetime

from flask import Flask, url_for, redirect, request
from flask_sqlalchemy import SQLAlchemy

from sqlalchemy.event import listens_for
from jinja2 import Markup

from flask_admin import Admin, form as sqlaform
from flask_admin.form import rules
from flask_admin.contrib import sqla


from flask.ext import admin, login
from flask.ext.admin import helpers, expose
from werkzeug.security import generate_password_hash, check_password_hash

from wtforms import form as wtform, fields, validators
from wtforms.fields.html5 import EmailField
form = wtform


# Create application
app = Flask(__name__, static_folder='files')

# Create dummy secrey key so we can use sessions
app.config['SECRET_KEY'] = '123456790'

# Create in-memory database
app.config['DATABASE_FILE'] = 'sample_db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + app.config['DATABASE_FILE']
app.config['SQLALCHEMY_ECHO'] = True
db = SQLAlchemy(app)

# Create directory for file fields to use
file_path = op.join(op.dirname(__file__), 'files')
try:
    os.mkdir(file_path)
except OSError:
    pass


# Create models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.Unicode(64))
    last_name = db.Column(db.Unicode(64))
    phone = db.Column(db.Unicode(32))
    affiliation = db.Column(db.Unicode(128))
    notes = db.Column(db.UnicodeText)

    email = db.Column(db.String(120))
    password = db.Column(db.String(64))

    def __repr__(self):
        if self.first_name is not None:
            first = self.first_name
        else:
            first = ""
        if self.last_name is not None:
            last = self.last_name
        else:
            last = ""

        template = "%s %s (%s)" % (first, last, self.email)
        return template.lstrip()

    # Flask-Login integration
    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


class Instrument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(128))

    def __repr__(self):
        return str(self.name)


class Protocol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    protocol = db.Column(db.UnicodeText())

    def __repr__(self):
        return str(self.name)


class Sample(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))

    location = db.Column(db.Unicode(256), index=True)

    owner_id = db.Column(db.Integer, db.ForeignKey(User.id), index=True)
    owner = db.relationship(User, backref='samples')

    instrument_id = db.Column(db.Integer, db.ForeignKey(Instrument.id), index=True)
    instrument = db.relationship(Instrument, backref='samples')

    protocol_id = db.Column(db.Integer, db.ForeignKey(Protocol.id), index=True)
    protocol = db.relationship(Protocol, backref='samples')

    date_collected = db.Column(db.DateTime)

    def __init__(self, *args, **kwargs):
        super(Sample, self).__init__(*args, **kwargs)
        if self.date_collected is None:
            self.date_collected = datetime.utcnow()


class SampleInformationTag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    description = db.Column(db.UnicodeText())
    sample_id = db.Column(db.Integer, db.ForeignKey(Sample.id, ondelete="CASCADE"), index=True)
    sample = db.relationship(Sample, backref='tags')

    def __repr__(self):
        return "%s: %s" % (self.name, self.description)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    file_type = db.Column(db.Unicode(64))
    path = db.Column(db.Unicode(128))
    sample_id = db.Column(db.Integer, db.ForeignKey(Sample.id, ondelete="CASCADE"), index=True)
    sample = db.relationship(Sample, backref='files')

    def __unicode__(self):
        return self.name


class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(64))
    path = db.Column(db.Unicode(128))

    def __unicode__(self):
        return self.name


# Delete hooks for models, delete files if models are getting deleted
@listens_for(File, 'after_delete')
def del_file(mapper, connection, target):
    if target.path:
        try:
            os.remove(op.join(file_path, target.path))
        except OSError:
            # Don't care if was not deleted because it does not exist
            pass


# Define login and registration forms (for flask-login)
class LoginForm(wtform.Form):
    email = EmailField(validators=[validators.required()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        user = self.get_user()

        if user is None:
            raise validators.ValidationError('Invalid user')

        # we're comparing the plaintext pw with the the hash from the db
        if not check_password_hash(user.password, self.password.data):
        # to compare plain text passwords use
        # if user.password != self.password.data:
            raise validators.ValidationError('Invalid password')

    def get_user(self):
        return db.session.query(User).filter_by(email=self.email.data).first()


class RegistrationForm(wtform.Form):
    first_name = fields.TextField(validators=[validators.required()])
    last_name = fields.TextField(validators=[validators.required()])
    phone = fields.TextField()
    affiliation = fields.TextField()

    email = EmailField('Email address', [validators.DataRequired(), validators.Email()])
    password = fields.PasswordField(validators=[validators.required()])

    def validate_login(self, field):
        if db.session.query(User).filter_by(email=self.email.data).count() > 0:
            raise validators.ValidationError('Duplicate username')


# Administrative views
class FileView(sqla.ModelView):
    # Override form field to use Flask-Admin FileUploadField
    form_overrides = {
        'path': sqlaform.FileUploadField
    }

    # Pass additional parameters to 'path' to FileUploadField constructor
    form_args = {
        'path': {
            'label': 'File',
            'base_path': file_path,
            'allow_overwrite': False
        }
    }

    def is_accessible(self):
        return login.current_user.is_authenticated()


class SampleView(sqla.ModelView):
    form_columns = ["name", "owner", "instrument", "protocol", "tags", "location", "date_collected"]
    inline_models = [SampleInformationTag]
    can_view_details = True

    column_details_list = ["name", "owner", "instrument", "protocol", "tags", "location", "date_collected"]

    def is_accessible(self):
        return login.current_user.is_authenticated()

    def _link_to_protocol(view, context, model, name):
        protocol = model.protocol
        print protocol
        if protocol is None:
            return Markup("")
        template = "<a href='%s'>%s</a>"
        link = str(url_for('protocol.details_view', id=protocol.id))
        rendered = template % (link, protocol.name)
        print rendered
        return Markup(rendered)

    column_formatters = {
        "protocol": _link_to_protocol
    }


class InstrumentView(sqla.ModelView):
    form_columns = ["name"]

    def is_accessible(self):
        return login.current_user.is_authenticated()


class ProtocolView(sqla.ModelView):
    form_columns = ["name", "protocol"]
    can_view_details = True

    def is_accessible(self):
        return login.current_user.is_authenticated()


class UserView(sqla.ModelView):
    """
    This class demonstrates the use of 'rules' for controlling the rendering of forms.
    """
    form_create_rules = [
        # Header and four fields. Email field will go above phone field.
        rules.FieldSet(('first_name', 'last_name', 'email', 'phone'), 'Personal'),
        # Separate header and few fields
        rules.Header('Affiliation'),
        rules.Field('affiliation'),
        # # String is resolved to form field, so there's no need to explicitly use `rules.Field`
        # 'country',
        # Show macro from Flask-Admin lib.html (it is included with 'lib' prefix)
        rules.Container('rule_macros.wrap', rules.Field('notes'))
    ]

    can_view_details = True

    form_excluded_columns = ['password']
    column_exclude_list = ['password']
    column_details_exclude_list = ['password']

    column_details_list = ['first_name', 'last_name', 'email', 'phone', 'samples', "notes"]

    # Use same rule set for edit page
    form_edit_rules = form_create_rules

    create_template = 'rule_create.html'
    edit_template = 'rule_edit.html'

    def is_accessible(self):
        return login.current_user.is_authenticated()


# Initialize flask-login
def init_login(app):
    login_manager = login.LoginManager()
    login_manager.init_app(app)

    # Create user loader function
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.query(User).get(user_id)


# Flask views
@app.route('/')
def index():
    return redirect('/admin/')


# Create customized index view class that handles login & registration
class MyAdminIndexView(admin.AdminIndexView):

    @expose('/')
    def index(self):
        app.logger.info("In index")
        if not login.current_user.is_authenticated():
            return redirect(url_for('.login_view'))
        return super(MyAdminIndexView, self).index()

    @expose('/login/', methods=('GET', 'POST'))
    def login_view(self):
        # handle user login
        app.logger.info("In Login View")
        form = LoginForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = form.get_user()
            login.login_user(user)

        if login.current_user.is_authenticated():
            return redirect(url_for('.index'))
        link = '<p>Don\'t have an account? <a href="' + url_for('.register_view') + '">Click here to register.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/register/', methods=('GET', 'POST'))
    def register_view(self):
        form = RegistrationForm(request.form)
        if helpers.validate_form_on_submit(form):
            user = User()

            form.populate_obj(user)
            # we hash the users password to avoid saving it as plaintext in the db,
            # remove to use plain text:
            user.password = generate_password_hash(form.password.data)

            db.session.add(user)
            db.session.commit()

            login.login_user(user)
            return redirect(url_for('.index'))
        link = '<p>Already have an account? <a href="' + url_for('.login_view') + '">Click here to log in.</a></p>'
        self._template_args['form'] = form
        self._template_args['link'] = link
        return super(MyAdminIndexView, self).index()

    @expose('/logout/')
    def logout_view(self):
        login.logout_user()
        return redirect(url_for('.index'))


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    db.drop_all()
    db.create_all()


# Create admin
admin_app = Admin(app, 'Sample Manager', template_mode='bootstrap3', index_view=MyAdminIndexView(), base_template='base_auth.html')

# Add views
admin_app.add_view(InstrumentView(Instrument, db.session))
admin_app.add_view(ProtocolView(Protocol, db.session))
admin_app.add_view(UserView(User, db.session, name='User'))
admin_app.add_view(SampleView(Sample, db.session, name='Sample'))
admin_app.add_view(FileView(File, db.session))


init_login(app)


if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = op.realpath(os.path.dirname(__file__))
    database_path = op.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(debug=True)
