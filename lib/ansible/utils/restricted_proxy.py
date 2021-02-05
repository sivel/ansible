# Copyright (c) 2020 Matt Martz <matt@sivel.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Make coding more python3-ish
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from collections import namedtuple
from functools import wraps
from typing import Any, Callable, EXCLUDED_ATTRIBUTES, Generic, List, Protocol, T, Type, Union
from typing import runtime_checkable  # pylint: disable=unused-import


# Protocol isn't a valid type here
class RestrictedInterface(Generic[T]):
    # Special type used to wrap our Protocols so we ignore a protocol
    # specified by a 3rd party library
    def __class_getitem__(cls, params):
        if not isinstance(params, tuple):
            params = (params,)
        for param in params:
            if not isinstance(param, type) or not issubclass(param, Protocol):
                raise TypeError(
                    f"Parameters to {cls.__name__}[...] must all be subclasses of Protocol")

            if not getattr(param, '_is_runtime_protocol', False):
                raise TypeError(
                    f"{param.__name__} must be runtime_checkable")
        return super(RestrictedInterface, cls).__class_getitem__(params)


ProtocolAttr = namedtuple('ProtocolAttr', ['attr', 'annotation', 'callable'])


def _get_protocol_attrs(cls: Type):
    """Copy of private function from typing, with a few modifications:

    1. return the type of annotations
    2. return whether the attr is callable

    """
    attrs = set()
    for base in cls.__mro__[:-1]:  # without object
        if base.__name__ in ('Protocol', 'Generic'):
            continue
        annotations = getattr(base, '__annotations__', {})
        for attr in list(base.__dict__.keys()) + list(annotations.keys()):
            if not attr.startswith('_abc_') and attr not in EXCLUDED_ATTRIBUTES:
                if attr in annotations:
                    attrs.add(ProtocolAttr(attr, annotations[attr], False))
                else:
                    attrs.add(
                        ProtocolAttr(
                            attr,
                            getattr(
                                base.__dict__[attr],
                                '__annotations__',
                                {}
                            ).get('return'),
                            True
                        )
                    )
    return attrs


def _restricted_proxify(func: Callable, annotations: List[Any]) -> Callable:
    """Wrapper to dynamically proxyify return values from callables"""
    @wraps(func)
    def inner(*args, **kwargs):
        return restricted_proxy(
            func(*args, **kwargs),
            annotations
        )
    return inner


def _no_init(self, *args, **kwargs):
    raise TypeError(
        'ProtocolProxy objects cannot be instantiated, but will still act like an instance'
    )


def _get_origin(obj: Any) -> Any:
    return getattr(obj, '__origin__', None)


class RestrictedProxy:
    """Base class of all restricted proxies that come from ``restricted_proxy``
    for use in ``issubclass`` checks
    """


def restricted_proxy(obj: Any, protocols: Any) -> Any:
    """Creates a restricted proxy of an object, limited by a list of ``RestrictedInterfaces``"""
    if _get_origin(protocols) is Union:
        # Unwind a Union like: Union[RestrictedInterface[Foo], RestrictedInterface[Bar]]
        protocols = protocols.__args__
    elif _get_origin(protocols) is RestrictedInterface:
        # Recursive calls may just pass a RestrictedInterface instead of a list
        protocols = [protocols]
    elif isinstance(protocols, type):
        # Recursive calls may pass something like `str`
        protocols = []

    # Our protocols used here *must* be wrapped in `RestrictedInterface`
    # RestrictedInterface enforces only accepting a Protocol subclass
    protocols = [p.__args__[0] for p in protocols if _get_origin(p) is RestrictedInterface]

    if not protocols:
        # No restriction, just pass the obj back
        return obj

    public = set()
    for protocol in protocols:
        # There is no way to make a union of multiple protocols
        # and use that union with an isinstance check
        if not isinstance(obj, protocol):
            raise TypeError(f'{obj} does not implement the interface defined by {protocol}')
        public.update(_get_protocol_attrs(protocol))

    dct = {}
    for attr in public:
        if attr.annotation:
            if attr.callable:
                # This will dynamically wrap the return with proxy
                # at call time
                wrapper = _restricted_proxify
            else:
                wrapper = restricted_proxy
            dct[attr.attr] = wrapper(
                getattr(obj, attr.attr),
                attr.annotation
            )
        else:
            dct[attr.attr] = getattr(obj, attr.attr)
    dct['__doc__'] = (
        f'RestrictedProxy of {obj.__class__.__name__} and may not match all documentation\n\n'
        f'{obj.__doc__}'
    )
    dct['__init__'] = _no_init

    return type(
        f'{obj.__class__.__name__}RestrictedProxy',
        (RestrictedProxy,),
        dct
    )
