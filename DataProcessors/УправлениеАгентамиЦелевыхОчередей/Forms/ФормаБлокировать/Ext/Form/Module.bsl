
&НаСервере
Процедура ПриСозданииНаСервере(Отказ, СтандартнаяОбработка)
	Абонент = Параметры.Абонент;
	Автор = ПараметрыСеанса.ТекущийПользователь.Наименование;
	ДатаНачала = ТекущаяДата();
КонецПроцедуры


#Область Заблокировать
&НаКлиенте
Процедура Заблокировать(Команда)
	Доступно = СтрДлина(Абонент);
	Доступно = Доступно И ЗначениеЗаполнено(Причина);
	Доступно = Доступно И ЗначениеЗаполнено(ДатаНачала);
	Доступно = Доступно И ЗначениеЗаполнено(ДатаОкончания);
	Доступно = Доступно И ДатаОкончания > ДатаНачала;
	Доступно = Доступно И ЗначениеЗаполнено(Автор);
	Если Не Доступно Тогда
		ПоказатьПредупреждение(, "Ошибки в заполненении реквизитов блокировки", 3);
		Возврат;
	КонецЕсли;
		
	Результат = ЗаблокироватьНаСервере(Абонент, ДатаОкончания, Автор, Причина);
	Если (ТипЗнч(Результат) = Тип("Строка")) И (ЗначениеЗаполнено(Результат)) Тогда
		Ответ = "Ошибка блокировки : " + СокрЛП(Результат);
		Сообщить(Ответ);
	КонецЕсли;
	
	Закрыть(Результат);
КонецПроцедуры

&НаСервереБезКонтекста
Функция ЗаблокироватьНаСервере(Абонент, ДатаОкончания, Автор, Причина)
	
	Результат = "error";
	Попытка	
		ОпределениеСервиса = Новый WSОпределения("http://astws.main.luidorauto.ru:8081/asterisk_ws/soap/description");
		ВебСервис = Новый WSПрокси(ОпределениеСервиса, "http://tempuri.org/", "asterisk_ws", "asterisk_ws"); 		
		Результат = ВебСервис.abonent_lock(Абонент, ДатаОкончания, Автор, Причина);
	Исключение
		Данные = "Абонент ="+ Абонент+ "; ДатаОкончания = "+ДатаОкончания+"; Автор = "+Автор+"; Причина ="+Причина;
		Комментарий = ОписаниеОшибки();
		ЗаписьЖурналаРегистрации("ВебСервис.abonent_lock", УровеньЖурналаРегистрации.Ошибка, ,Данные, Комментарий);
	КонецПопытки;
	Возврат Результат;

КонецФункции
#КонецОбласти