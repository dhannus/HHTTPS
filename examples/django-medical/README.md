# Django + HHTTPS — Medical Q&A example

A medical question platform where only verified doctors (trust ≥ 90) may answer.

## Setup
```python
# settings.py
MIDDLEWARE = [..., 'hhttps_middleware.HHTPPSMiddleware']

# urls.py
from .views import answer_view, question_view
urlpatterns = [
    path('answer/<int:question_id>/', answer_view),
    path('question/<int:question_id>/', question_view),
]
```

## Endpoints
| Path | Auth |
|---|---|
| GET  /question/<id>/   | public — shows question; reveals "answer" form only if verified doctor |
| POST /answer/<id>/     | role=medical_professional, trust ≥ 90 |
