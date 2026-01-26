import importlib
from functools import lru_cache
from types import ModuleType
from typing import Any, Callable, Dict, cast


TransformFn = Callable[[Any, Any, str], Dict[str, Any]]


def _import_transform_module(module_name: str) -> ModuleType:
    return importlib.import_module(f"transforms.{module_name}")


@lru_cache(maxsize=None)
def get_transform(source_key: str) -> TransformFn:
    mod = _import_transform_module(source_key)

    fn = getattr(mod, "transform", None)
    if not callable(fn):
        raise RuntimeError(f"Transform module transforms.{source_key} does not export callable 'transform'")

    return cast(TransformFn, fn)
