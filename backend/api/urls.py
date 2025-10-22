from rest_framework.routers import SimpleRouter

from .views import UserViewSet, StorageViewSet

router = SimpleRouter()
router.register(r'user', UserViewSet, basename='user')
router.register(r'storage', StorageViewSet, basename='storage')

urlpatterns = router.urls