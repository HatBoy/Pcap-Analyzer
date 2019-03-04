#coding:UTF-8
__author__ = 'dj'

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms.validators import DataRequired, AnyOf

#上传表单
class Upload(FlaskForm):
    pcap = FileField('pcap', validators=[DataRequired()])

#协议过滤表单
class ProtoFilter(FlaskForm):
    value = FileField('value')
    filter_type = FileField('filter_type', validators=[DataRequired(), AnyOf([u'all', u'proto', u'ipsrc', u'ipdst'])])
