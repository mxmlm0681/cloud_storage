from rest_framework.permissions import BasePermission

class IsAuthenticatedOrViewFile(BasePermission):
    """
    Позволяет доступ к методу view_file, download_file_by_token без аутентификации,
    и требует аутентификацию для остальных методов.
    """
    def has_permission(self, request, view):
        # Проверяем, если метод view_file или download_file_by_token вызывается через GET-запрос
        if request.method == 'GET':
            id_user = view.kwargs.get('id_user')
            id_file = view.kwargs.get('id_file')
            token = view.kwargs.get('token')

            '''' Проверка, что был передан id_user и id_file или token - это условия для использования
             `view_file` или 'download_file_by_token 
            '''
            if (id_user and id_file) or token:
                return True  # Разрешаем, если это метод view_file или download_file_by_token

        # Если не view_file или download_file_by_token, проверяем аутентификацию
        return request.user.is_authenticated