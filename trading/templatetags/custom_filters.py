from django import template

register = template.Library()

@register.filter
def usd_format(value):
    return "${:,.2f}".format(value)